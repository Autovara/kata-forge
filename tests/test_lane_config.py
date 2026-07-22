from __future__ import annotations

import json

from kata_forge.cli import main
from kata_forge.lane_config import apply_lane_to_env, editable_path, env_patch, lane_entry, render_snippet
from kata_forge.spec import validate_spec

SPEC = validate_spec(subnet_number=126, pack="sn126__poker44", evaluator_id="sn126_poker44")

SAMPLE_ENV = (
    'KATA_LANES=\'[{"lane_id":"sn60__bitsec","pack":"sn60__bitsec","mode":"miner",'
    '"evaluator":"sn60_bitsec"}]\'\n'
    "KATA_SUBNET_PLUGIN_EDITABLE_PATHS=/srv/kata-sn60\n"
)


def test_lane_entry_shape() -> None:
    entry = lane_entry(SPEC, release_path="/srv/kata-sn126/pin.json", sample_size=52)
    assert entry["lane_id"] == "sn126__poker44"
    assert entry["evaluator"] == "sn126_poker44"
    assert entry["mode"] == "miner"
    assert entry["source_repos"] == ["Autovara/kata-sn126"]
    assert entry["challenge_config"] == {"pinned_release_path": "/srv/kata-sn126/pin.json", "sample_size": 52}
    # empty config when unspecified
    assert lane_entry(SPEC)["challenge_config"] == {}


def test_editable_path_and_snippet() -> None:
    path = editable_path(SPEC)
    assert path == "/srv/kata-sn126"
    snippet = render_snippet(SPEC, lane_entry(SPEC), path)
    assert "sn126__poker44" in snippet and "/srv/kata-sn126" in snippet


def test_apply_lane_appends_and_keeps_existing() -> None:
    out = apply_lane_to_env(SAMPLE_ENV, lane_entry(SPEC), "/srv/kata-sn126")
    lanes_line = next(line for line in out.splitlines() if line.startswith("KATA_LANES="))
    lanes = json.loads(lanes_line[len("KATA_LANES=") + 1 : -1])
    assert [lane["lane_id"] for lane in lanes] == ["sn60__bitsec", "sn126__poker44"]  # kept + added
    paths_line = next(line for line in out.splitlines() if line.startswith("KATA_SUBNET_PLUGIN"))
    assert paths_line.endswith("/srv/kata-sn60:/srv/kata-sn126")


def test_apply_is_idempotent() -> None:
    once = apply_lane_to_env(SAMPLE_ENV, lane_entry(SPEC), "/srv/kata-sn126")
    twice = apply_lane_to_env(once, lane_entry(SPEC), "/srv/kata-sn126")
    assert once == twice
    assert env_patch(once, lane_entry(SPEC), "/srv/kata-sn126") == ""  # nothing to change


def test_apply_when_keys_absent_adds_them() -> None:
    out = apply_lane_to_env("SOME_OTHER=1\n", lane_entry(SPEC), "/srv/kata-sn126")
    assert "KATA_LANES='[" in out
    assert "KATA_SUBNET_PLUGIN_EDITABLE_PATHS=/srv/kata-sn126" in out


def test_env_patch_is_a_valid_unified_diff() -> None:
    patch = env_patch(SAMPLE_ENV, lane_entry(SPEC), "/srv/kata-sn126")
    assert patch.startswith("--- a/srv/kata-bot/.env")
    assert "+++ b/srv/kata-bot/.env" in patch and "@@" in patch
    assert "sn126__poker44" in patch


def test_cli_lane_config_prints_snippet(capsys) -> None:
    rc = main(["lane-config", "--subnet", "126", "--pack", "sn126__poker44", "--evaluator", "sn126_poker44"])
    assert rc == 0
    assert "sn126__poker44" in capsys.readouterr().out


def test_cli_lane_config_writes_patch(tmp_path, capsys) -> None:
    env_file = tmp_path / ".env"
    env_file.write_text(SAMPLE_ENV, encoding="utf-8")
    out_file = tmp_path / "lane.patch"
    rc = main(
        ["lane-config", "--subnet", "126", "--pack", "sn126__poker44", "--evaluator", "sn126_poker44",
         "--env", str(env_file), "--out", str(out_file)]
    )
    assert rc == 0
    assert out_file.read_text().startswith("--- a/")
    assert env_file.read_text() == SAMPLE_ENV  # NEVER mutates the .env
