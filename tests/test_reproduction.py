"""F3: prove a generated skeleton is a real, discoverable Kata plugin.

Integration test -- it scaffolds the SN126 skeleton, installs it (with kata) into a throwaway
venv, runs the *generated* skeleton's own test suite, and checks entry-point discovery + that
the unfilled methods raise. Skipped when uv or the local kata checkout is unavailable.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

from kata_forge.generator import generate
from kata_forge.spec import validate_spec

_STUDY = Path(__file__).resolve().parents[2]
_KATA = _STUDY / "kata"

pytestmark = pytest.mark.skipif(
    shutil.which("uv") is None or not _KATA.exists(),
    reason="needs uv and a local ../kata checkout",
)

_DISCOVERY_CHECK = '''
from kata.plugins.discovery import plugin_for_evaluator, plugin_for_pack

plugin = plugin_for_evaluator("sn126_poker44")
assert plugin is not None, "plugin not discovered via entry point"
assert plugin is plugin_for_pack("sn126__poker44", "miner")
assert plugin.evaluator_id == "sn126_poker44"
assert plugin.pack == "sn126__poker44"
assert plugin.mode == "miner"
assert plugin.environment_spec().network == "none"

# the four subnet-specific methods are stubs until filled
try:
    plugin.sample_problems(seed="s", config={})
    raise SystemExit("sample_problems did not raise")
except NotImplementedError:
    pass
try:
    plugin.score(None, None)
    raise SystemExit("score did not raise")
except NotImplementedError:
    pass
print("DISCOVERY_OK")
'''


def _run(cmd: list[str]) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True, check=False)


def test_generated_skeleton_installs_runs_and_is_discoverable(tmp_path) -> None:
    spec = validate_spec(subnet_number=126, pack="sn126__poker44", evaluator_id="sn126_poker44")
    generate(spec, tmp_path)
    repo = tmp_path / "kata-sn126"
    venv = tmp_path / ".venv"
    python = str(venv / "bin" / "python")

    assert _run(["uv", "venv", str(venv)]).returncode == 0
    # Install kata + pytest first, then the generated skeleton with --no-deps (its pyproject's
    # [tool.uv.sources] points kata at ../kata, which only exists in a real side-by-side layout).
    base = _run(["uv", "pip", "install", "--python", python, "-e", str(_KATA), "pytest"])
    assert base.returncode == 0, base.stderr
    install = _run(["uv", "pip", "install", "--python", python, "--no-deps", "-e", str(repo)])
    assert install.returncode == 0, install.stderr

    # 1. The GENERATED skeleton's own tests pass (discovery + attrs + env spec).
    generated_tests = _run([python, "-m", "pytest", "-q", str(repo / "tests")])
    assert generated_tests.returncode == 0, generated_tests.stdout + generated_tests.stderr

    # 2. Entry-point discovery resolves it and the unfilled methods raise.
    check_file = tmp_path / "discovery_check.py"
    check_file.write_text(_DISCOVERY_CHECK, encoding="utf-8")
    check = _run([python, str(check_file)])
    assert check.returncode == 0 and "DISCOVERY_OK" in check.stdout, check.stdout + check.stderr
