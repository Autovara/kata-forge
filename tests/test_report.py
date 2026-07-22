from __future__ import annotations

from pathlib import Path

import pytest

from kata_forge.anchors import Anchor, AnchorReport
from kata_forge.cli import main
from kata_forge.deps import DepReport
from kata_forge.report import inject_anchor_todos, render_analysis, write_extract
from kata_forge.resolver import ResolvedRepo
from kata_forge.spec import validate_spec

POKER44 = Path("/tmp/poker44-research")


def _anchors() -> AnchorReport:
    return AnchorReport(
        scorer=Anchor("scorer", "poker44/score/scoring.py", "reward", 94,
                      "def reward(y_pred, y_true) -> tuple[float, dict]", "", "high"),
        benchmark=Anchor("benchmark", "neurons/validator.py", "api.poker44.net", 55,
                         "https://api.poker44.net/x", "", "high"),
        miner=Anchor("miner", "poker44/validator/synapse.py", "DetectionSynapse", 10,
                     "class DetectionSynapse(bt.Synapse)", "", "high"),
        candidates={},
    )


def _deps() -> DepReport:
    return DepReport("FREE", ["numpy"], [], [], [], [], ["requirements.txt"])


def _resolved(path: Path) -> ResolvedRepo:
    return ResolvedRepo(source=str(path), path=path, commit="abc123", was_cloned=False)


def test_render_analysis_names_the_anchors() -> None:
    text = render_analysis(subnet=126, resolved=_resolved(Path("/tmp/r")), deps=_deps(), anchors=_anchors())
    assert "poker44/score/scoring.py:94" in text
    assert "api.poker44.net" in text
    assert "DetectionSynapse" in text
    assert "FREE" in text
    assert "Open questions" in text  # surfaces what it can't decide


def test_render_analysis_missing_anchor_is_flagged() -> None:
    anchors = AnchorReport(scorer=None, benchmark=None, miner=None, candidates={})
    text = render_analysis(subnet=1, resolved=_resolved(Path("/tmp/r")), deps=_deps(), anchors=anchors)
    assert "not found" in text


def test_inject_anchor_todos_targets_the_right_stubs() -> None:
    src = (
        "class P:\n"
        "    def sample_problems(self):\n"
        "        raise NotImplementedError\n"
        "    def score(self, raw):\n"
        "        raise NotImplementedError\n"
        "    def run_candidate(self):\n"
        "        raise NotImplementedError\n"
    )
    out = inject_anchor_todos(src, _anchors())
    lines = out.splitlines()
    # the scorer anchor comment sits directly above def score(
    score_idx = next(i for i, ln in enumerate(lines) if ln.strip().startswith("def score("))
    assert "scoring.py:94" in lines[score_idx - 2]
    assert "ANCHOR" in lines[score_idx - 3]
    # each stub gets its own kind
    assert any("DetectionSynapse" in ln for ln in lines)
    assert any("api.poker44.net" in ln for ln in lines)
    # injection keeps the file valid python
    compile(out, "plugin.py", "exec")


def test_write_extract_report_only(tmp_path) -> None:
    repo = tmp_path / "poker44-research"
    repo.mkdir()
    outputs = write_extract(
        out_dir=tmp_path / "out", subnet=126, resolved=_resolved(repo),
        deps=_deps(), anchors=_anchors(),
    )
    assert outputs.analysis_path.name == "poker44-research-analysis.md"
    assert outputs.analysis_path.is_file()
    assert outputs.scaffold_root is None


def test_write_extract_with_scaffold_injects_anchors(tmp_path) -> None:
    repo = tmp_path / "poker44-research"
    repo.mkdir()
    spec = validate_spec(subnet_number=126, pack="sn126__poker44", evaluator_id="sn126_poker44")
    outputs = write_extract(
        out_dir=tmp_path / "out", subnet=126, resolved=_resolved(repo),
        deps=_deps(), anchors=_anchors(), spec=spec,
    )
    assert outputs.scaffold_root == (tmp_path / "out" / "kata-sn126")
    plugin = next(p for p in outputs.scaffold_paths if p.name == "plugin.py")
    body = plugin.read_text(encoding="utf-8")
    assert "ANCHOR (kata-forge extract)" in body
    assert "poker44/score/scoring.py:94" in body
    compile(body, "plugin.py", "exec")  # still valid python


def test_cli_extract_out_without_spec_writes_report_only(tmp_path, capsys) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "requirements.txt").write_text("numpy\n", encoding="utf-8")
    rc = main(["extract", "--repo", str(repo), "--out", str(tmp_path / "out")])
    assert rc == 0
    out = capsys.readouterr().out
    assert "wrote:" in out
    assert (tmp_path / "out" / "repo-analysis.md").is_file()


@pytest.mark.skipif(not POKER44.exists(), reason="poker44 clone not present")
def test_cli_extract_poker44_full_scaffold(tmp_path, capsys) -> None:
    rc = main([
        "extract", "--repo", str(POKER44), "--out", str(tmp_path / "out"),
        "--subnet", "126", "--pack", "sn126__poker44", "--evaluator", "sn126_poker44",
    ])
    assert rc == 0
    plugin = tmp_path / "out" / "kata-sn126" / "kata_sn126" / "plugin.py"
    body = plugin.read_text(encoding="utf-8")
    assert "poker44/score/scoring.py:94" in body  # real anchor injected
    assert "DetectionSynapse" in body
    compile(body, "plugin.py", "exec")
