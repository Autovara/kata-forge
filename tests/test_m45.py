"""M4.5 -- paid lane-config (egress + secret placeholders, no real keys) + the opt-in --llm seam."""

from __future__ import annotations

import pytest

from kata_forge.anchors import Anchor, AnchorReport
from kata_forge.cli import main
from kata_forge.lane_config import (
    apply_lane_to_env,
    env_patch,
    lane_entry,
    secret_placeholder_block,
)
from kata_forge.llm import LlmUnavailable, build_prompt, default_drafter, llm_enabled
from kata_forge.report import inject_anchor_todos, write_extract
from kata_forge.resolver import ResolvedRepo
from kata_forge.spec import validate_spec

SPEC = validate_spec(subnet_number=126, pack="sn126__poker44", evaluator_id="sn126_poker44")


# --- Part A: paid lane-config -------------------------------------------------

def test_lane_entry_gets_egress_block() -> None:
    entry = lane_entry(SPEC, allowed_hosts=["api.openai.com"], required_secrets=["OPENAI_API_KEY"])
    assert entry["egress"] == {
        "allowed_hosts": ["api.openai.com"],
        "required_secrets": ["OPENAI_API_KEY"],
    }


def test_lane_entry_no_egress_when_free() -> None:
    assert "egress" not in lane_entry(SPEC)


def test_secret_placeholders_are_commented_no_values() -> None:
    block = secret_placeholder_block(["OPENAI_API_KEY", "APIFY_TOKEN"], 126)
    assert block[0].startswith("# --- SN126 lane secrets")
    assert "# APIFY_TOKEN=" in block and "# OPENAI_API_KEY=" in block
    assert all(line.startswith("#") for line in block)  # never an uncommented real assignment


def test_apply_lane_appends_placeholder_idempotently() -> None:
    entry = lane_entry(SPEC, required_secrets=["OPENAI_API_KEY"])
    base = "KATA_LANES='[]'\n"
    once = apply_lane_to_env(base, entry, "/srv/kata-sn126", secret_placeholders=["OPENAI_API_KEY"])
    assert "# OPENAI_API_KEY=" in once
    # already-set secret is not re-added
    with_key = once + "OPENAI_API_KEY=sk-real\n"
    twice = apply_lane_to_env(with_key, entry, "/srv/kata-sn126", secret_placeholders=["OPENAI_API_KEY"])
    assert twice.count("# OPENAI_API_KEY=") == once.count("# OPENAI_API_KEY=")


def test_env_patch_includes_secret_placeholder() -> None:
    entry = lane_entry(SPEC, required_secrets=["OPENAI_API_KEY"])
    patch = env_patch("KATA_LANES='[]'\n", entry, "/srv/kata-sn126", secret_placeholders=["OPENAI_API_KEY"])
    assert "+# OPENAI_API_KEY=" in patch
    assert "sk-" not in patch  # no real value ever


def test_cli_lane_config_paid_repo(tmp_path, capsys) -> None:
    repo = tmp_path / "paid"
    repo.mkdir()
    (repo / "a.py").write_text(
        'import os\nk=os.environ["OPENAI_API_KEY"]\nU="https://api.openai.com/v1"\n', encoding="utf-8"
    )
    rc = main([
        "lane-config", "--subnet", "126", "--pack", "sn126__poker44",
        "--evaluator", "sn126_poker44", "--repo", str(repo),
    ])
    assert rc == 0
    out = capsys.readouterr().out
    assert "egress" in out and "OPENAI_API_KEY" in out and "api.openai.com" in out


# --- Part B: the opt-in --llm seam -------------------------------------------

def _anchors() -> AnchorReport:
    return AnchorReport(
        scorer=Anchor("scorer", "s.py", "reward", 1, "def reward(a,b)->float", "", "high"),
        benchmark=None,
        miner=None,
        candidates={},
    )


def test_llm_disabled_by_default(monkeypatch) -> None:
    monkeypatch.delenv("KATA_FORGE_LLM", raising=False)
    assert llm_enabled() is False
    with pytest.raises(LlmUnavailable, match="KATA_FORGE_LLM"):
        default_drafter()


def test_build_prompt_grounds_in_anchor() -> None:
    prompt = build_prompt("score", _anchors().scorer, SPEC)
    assert "Poker44Plugin.score" in prompt and "s.py:1 reward" in prompt


def test_injected_drafter_adds_comment_only_draft(tmp_path) -> None:
    resolved = ResolvedRepo(source=str(tmp_path), path=tmp_path, commit=None, was_cloned=False)
    (tmp_path / "requirements.txt").write_text("numpy\n", encoding="utf-8")
    outputs = write_extract(
        out_dir=tmp_path / "out", subnet=126, resolved=resolved, anchors=_anchors(),
        spec=SPEC, drafter=lambda prompt: "return 1.0  # drafted",
    )
    body = next(p for p in outputs.scaffold_paths if p.name == "plugin.py").read_text()
    assert "LLM DRAFT" in body
    assert "# return 1.0  # drafted" in body  # injected as a comment
    compile(body, "plugin.py", "exec")  # draft never breaks the file


def test_raising_drafter_is_skipped(tmp_path) -> None:
    def bad(prompt: str) -> str:
        raise LlmUnavailable("nope")

    src = "class P:\n    def score(self):\n        raise NotImplementedError\n"
    # a raising drafter yields no drafts, so the plugin is unchanged apart from the anchor comment
    from kata_forge.report import _llm_drafts

    assert _llm_drafts(bad, _anchors(), SPEC) == {}
    assert "LLM DRAFT" not in inject_anchor_todos(src, _anchors(), None)


def test_cli_llm_flag_without_provider_notes_and_continues(tmp_path, capsys, monkeypatch) -> None:
    monkeypatch.delenv("KATA_FORGE_LLM", raising=False)
    repo = tmp_path / "r"
    repo.mkdir()
    (repo / "score.py").write_text("def reward(a, b) -> float:\n    return 1.0\n", encoding="utf-8")
    rc = main([
        "extract", "--repo", str(repo), "--out", str(tmp_path / "out"),
        "--subnet", "126", "--pack", "sn126__poker44", "--evaluator", "sn126_poker44", "--llm",
    ])
    assert rc == 0
    out = capsys.readouterr().out
    assert "llm:" in out and "KATA_FORGE_LLM" in out  # clear seam-not-wired note
    assert (tmp_path / "out" / "kata-sn126").is_dir()  # scaffold still written
