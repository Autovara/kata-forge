from __future__ import annotations

import json

from kata_forge.cli import main
from kata_forge.lane_config import (
    apply_lane_to_env,
    editable_path,
    env_patch,
    lane_entry,
    render_snippet,
)
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
    assert paths_line.endswith("/srv/kata-sn60,/srv/kata-sn126")  # comma-joined, not colon


def _consumer_split(env_line: str) -> list[str]:
    """Reproduce kata-bot's parser exactly (orchestrator.subnet_plugin_uv_args: raw.split(',',))."""
    raw = env_line[len("KATA_SUBNET_PLUGIN_EDITABLE_PATHS=") :]
    return [spec.strip() for spec in raw.split(",") if spec.strip()]


def test_two_lane_editable_paths_parse_into_two_for_the_consumer() -> None:
    # Regression for the shipped colon/comma bug: a second lane must yield TWO --with-editable
    # paths under the consumer's comma split, not one bogus "a:b" token.
    out = apply_lane_to_env(SAMPLE_ENV, lane_entry(SPEC), "/srv/kata-sn126")
    paths_line = next(line for line in out.splitlines() if line.startswith("KATA_SUBNET_PLUGIN"))
    parsed = _consumer_split(paths_line)
    assert parsed == ["/srv/kata-sn60", "/srv/kata-sn126"]
    assert not any(":" in p for p in parsed)  # no colon-joined path survives


def test_legacy_colon_value_is_migrated_to_commas() -> None:
    # A value written by the OLD (buggy) generator is colon-joined. Adding a lane must migrate the
    # whole value to commas, not leave the legacy part as one invalid consumer token.
    legacy = "KATA_SUBNET_PLUGIN_EDITABLE_PATHS=/srv/a:/srv/b\n"
    out = apply_lane_to_env(legacy, lane_entry(SPEC), "/srv/kata-sn126")
    paths_line = next(line for line in out.splitlines() if line.startswith("KATA_SUBNET_PLUGIN"))
    parsed = _consumer_split(paths_line)
    assert parsed == ["/srv/a", "/srv/b", "/srv/kata-sn126"]  # legacy colon absorbed
    assert not any(":" in p for p in parsed)


def test_legacy_colon_value_dedupes_existing_path() -> None:
    legacy = "KATA_SUBNET_PLUGIN_EDITABLE_PATHS=/srv/a:/srv/kata-sn126\n"
    out = apply_lane_to_env(legacy, lane_entry(SPEC), "/srv/kata-sn126")
    paths_line = next(line for line in out.splitlines() if line.startswith("KATA_SUBNET_PLUGIN"))
    assert _consumer_split(paths_line) == ["/srv/a", "/srv/kata-sn126"]  # not duplicated


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
