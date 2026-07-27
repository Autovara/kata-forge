"""S7: the one-command transactional build (plan 4.2).

Exercises the whole chain with a scripted git runner and an injected wheel builder, so no network,
no clone, and no untrusted build backend runs in the test process.
"""
from __future__ import annotations

import json
import os

import pytest

from kata_forge.build import (
    BUILD_STATE_FILENAME,
    MANIFEST_FILENAME,
    SBOM_FILENAME,
    STATES,
    BuildError,
    BuildInputs,
    BuildRefused,
    build,
    validate_output_root,
)
from kata_forge.decision import REFUSE, VENDOR
from kata_forge.onboard import INTEGRATION_DECISION_FILENAME
from kata_forge.spec import SubnetSpec
from kata_forge.trusted_input import TrustedInputError

GOOD = "https://github.com/Autovara/poker44"
SHA = "e" * 40
MIT = "MIT License\n\nPermission is hereby granted, free of charge, to any person obtaining a copy\n"

FREE_SOURCE = {"LICENSE": MIT, "requirements.txt": "numpy\n", "scorer.py": "def score(x): return x\n"}


class ScriptedGit:
    def __init__(self, files, head=SHA):
        self.files, self.head = files, head

    def __call__(self, args):
        sub = next((a for a in args if a in ("clone", "checkout", "rev-parse")), None)
        if sub == "clone":
            from pathlib import Path
            dest = Path(args[-1])
            dest.mkdir(parents=True, exist_ok=True)
            for rel, text in self.files.items():
                (dest / rel).write_text(text, encoding="utf-8")
            return (0, "", "")
        return (0, self.head, "") if sub == "rev-parse" else (0, "", "")


def fake_wheel(plugin_dir, dist_dir):
    """Stands in for the compartmented wheel build. Deterministic so builds stay idempotent."""
    dist_dir.mkdir(parents=True, exist_ok=True)
    wheel = dist_dir / "kata_sn44-0.1.0-py3-none-any.whl"
    wheel.write_text("fake wheel", encoding="utf-8")
    return wheel


@pytest.fixture
def out_root(tmp_path):
    root = tmp_path / "out"
    root.mkdir(mode=0o700)
    return root


def _spec():
    return SubnetSpec(subnet_number=44, pack="sn44__poker44", evaluator_id="sn44_poker44",
                      mode="miner", name="poker44")


def _build(out_root, **over):
    kwargs = dict(output_root=out_root, spec=_spec(), repo=GOOD,
                  kata_rev="k1", kata_bot_rev="b1", kata_forge_rev="f1",
                  kata_tree_hash="a" * 64, git_runner=ScriptedGit(FREE_SOURCE),
                  wheel_builder=fake_wheel, vendor_closure_files=2)
    kwargs.update(over)
    return build(**kwargs)


# ---- output root -----------------------------------------------------------------------------
def test_output_root_must_be_absolute_private_and_owned(tmp_path):
    good = tmp_path / "ok"
    good.mkdir(mode=0o700)
    assert validate_output_root(good) == good.resolve()

    with pytest.raises(BuildError, match="absolute"):
        validate_output_root("relative/path")
    with pytest.raises(BuildError, match="does not exist"):
        validate_output_root(tmp_path / "absent")

    loose = tmp_path / "loose"
    loose.mkdir(mode=0o755)
    with pytest.raises(BuildError, match="0700"):
        validate_output_root(loose)


@pytest.mark.parametrize("forbidden", ["/srv", "/srv/kata-bot/out", "/etc/x", "/usr/local/out"])
def test_the_build_never_writes_live_state(forbidden):
    """'build is not deployment' -- the boundary this whole command exists to hold."""
    with pytest.raises(BuildError, match="live state"):
        validate_output_root(forbidden)


# ---- build identity --------------------------------------------------------------------------
def test_the_build_id_is_the_hash_of_its_inputs():
    base = BuildInputs(source_url=GOOD, source_commit=SHA, kata_rev="k", kata_bot_rev="b",
                       kata_forge_rev="f")
    assert base.build_id() == BuildInputs(**base.canonical()).build_id()  # deterministic
    for field, value in [("source_commit", "f" * 40), ("kata_rev", "k2"), ("attempt_nonce", "2")]:
        changed = BuildInputs(**{**base.canonical(), field: value})
        assert changed.build_id() != base.build_id(), f"{field} must change the build id"


def test_the_build_id_covers_every_pinned_revision():
    canonical = BuildInputs(source_url=GOOD, source_commit=SHA, kata_rev="k", kata_bot_rev="b",
                            kata_forge_rev="f").canonical()
    assert set(canonical) == {"source_url", "source_commit", "kata_rev", "kata_bot_rev",
                              "kata_forge_rev", "policy_version", "attempt_nonce"}


# ---- the happy path --------------------------------------------------------------------------
def test_a_free_permissive_repo_emits_a_verified_bundle(out_root):
    result = _build(out_root)

    assert result.state == "verified" and result.mode == VENDOR and result.installable
    bundle = result.bundle_dir
    assert bundle.name == result.build_id and bundle.parent == out_root
    for required in (MANIFEST_FILENAME, BUILD_STATE_FILENAME, SBOM_FILENAME,
                     INTEGRATION_DECISION_FILENAME):
        assert (bundle / required).is_file(), f"the bundle must carry {required}"
    assert list(bundle.glob("dist/*.whl")), "a pre-built wheel is mandatory"
    assert list(bundle.glob("plugin/**/*.py")), "the plugin source must be in the bundle"


def test_the_bundle_contains_no_installer_or_service_state(out_root):
    """'never install.sh, systemctl, or live state' -- the forge emits declarations only."""
    bundle = _build(out_root).bundle_dir
    names = [p.name.lower() for p in bundle.rglob("*") if p.is_file()]
    for forbidden in ("install.sh", "setup.sh", "kata-sn44.service", "kata-sn44.timer"):
        assert forbidden not in names
    body = (bundle / MANIFEST_FILENAME).read_text()
    assert "systemctl" not in body and "ExecStart" not in body


def test_the_manifest_pins_the_source_and_the_abi(out_root):
    manifest = json.loads((_build(out_root).bundle_dir / MANIFEST_FILENAME).read_text())
    assert manifest["build_inputs"]["source_commit"] == SHA
    assert manifest["build_inputs"]["source_url"] == GOOD
    assert manifest["abi"]["kata_tree_hash"] == "a" * 64
    assert manifest["registry_change"]["lane"]["upstream_commit"] == SHA


def test_the_sbom_is_deterministic(out_root, tmp_path):
    first = json.loads((_build(out_root).bundle_dir / SBOM_FILENAME).read_text())
    other = tmp_path / "out2"
    other.mkdir(mode=0o700)
    second = json.loads((_build(other).bundle_dir / SBOM_FILENAME).read_text())
    # A nondeterministic SBOM lands in the tree manifest and would break build idempotence.
    assert first == second
    assert {c["name"] for c in first["components"]} >= {"numpy"}


# ---- idempotence and --new-attempt ------------------------------------------------------------
def test_the_same_input_is_idempotent_and_does_not_re_emit(out_root):
    first = _build(out_root)
    second = _build(out_root)
    assert second.build_id == first.build_id and second.reused
    assert second.bundle_dir == first.bundle_dir
    assert [d.name for d in out_root.iterdir() if d.is_dir() and not d.name.startswith(".")] == \
        [first.build_id]


def test_new_attempt_produces_a_different_build(out_root):
    first = _build(out_root)
    second = _build(out_root, new_attempt=True)
    assert second.build_id != first.build_id and not second.reused
    assert second.state == "verified"


def test_a_different_commit_is_a_different_build(out_root):
    first = _build(out_root)
    second = _build(out_root, git_runner=ScriptedGit(FREE_SOURCE, head="b" * 40))
    assert second.build_id != first.build_id


def test_there_is_no_force_overwrite():
    import inspect
    assert "force" not in inspect.signature(build).parameters


# ---- refusals --------------------------------------------------------------------------------
def test_an_unknown_input_refuses_without_guessing(out_root):
    for bad in ("/srv/kata", "git@github.com:o/r.git", "https://gitlab.com/o/r"):
        with pytest.raises(TrustedInputError):
            _build(out_root, repo=bad)
    assert not any(out_root.iterdir()), "a refused input must not leave a build behind"


def test_an_embedded_credential_refuses_and_emits_no_manifest(out_root):
    leaked = "ghp_" + "Z" * 36
    result = _build(out_root, git_runner=ScriptedGit({**FREE_SOURCE, "c.py": f"T='{leaked}'\n"}))

    assert result.state == "refused" and not result.installable
    # A refusal is retained for review, but has NO manifest -- so it can never be staged.
    assert not (result.bundle_dir / MANIFEST_FILENAME).exists()
    assert (result.bundle_dir / INTEGRATION_DECISION_FILENAME).is_file()
    assert leaked not in (result.bundle_dir / INTEGRATION_DECISION_FILENAME).read_text()


def test_a_paid_validator_refuses(out_root):
    result = _build(out_root, git_runner=ScriptedGit({**FREE_SOURCE, "requirements.txt": "openai\n"}))
    assert result.state == "refused" and result.mode == REFUSE
    assert "not free" in result.reason


def test_a_failed_wheel_build_is_never_installable(out_root):
    def refuse(_plugin, _dist):
        raise BuildRefused("cannot build the plugin wheel in an isolated compartment")

    result = _build(out_root, wheel_builder=refuse)
    assert result.state == "refused" and not result.installable
    assert not (result.bundle_dir / MANIFEST_FILENAME).exists()


# ---- transactional emission --------------------------------------------------------------------
def test_nothing_is_left_at_the_build_id_until_promotion(out_root):
    """A crash mid-build must not leave something that looks finished."""
    seen = {}

    def crash(plugin_dir, dist_dir):
        seen["ids"] = [d.name for d in out_root.iterdir()]
        raise RuntimeError("host died mid-build")

    with pytest.raises(RuntimeError):
        _build(out_root, wheel_builder=crash)
    # At crash time only a dot-prefixed staging directory existed.
    assert all(name.startswith(".") for name in seen["ids"])
    assert not any(p.is_dir() and not p.name.startswith(".") for p in out_root.iterdir())


def test_the_build_state_records_only_legal_states(out_root):
    state = json.loads((_build(out_root).bundle_dir / BUILD_STATE_FILENAME).read_text())
    assert state["state"] in STATES and state["state"] == "verified"
    assert state["conformance"] == "passed"
    # The pins the S4 installer cross-checks against the manifest.
    assert state["evaluator_id"] == "sn44_poker44" and state["kata_tree_hash"] == "a" * 64


def test_the_build_refuses_to_run_as_root(out_root, monkeypatch):
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    with pytest.raises(BuildError, match="must not run as root"):
        validate_output_root(out_root)


def test_an_unexpected_failure_is_recorded_as_failed_and_never_promoted(out_root):
    """`failed` is distinct from `refused`: a refusal is a policy answer, a failure is the build
    breaking. Both must be un-stageable, but only the refusal is a reviewable outcome."""
    def crash(_plugin, _dist):
        raise RuntimeError("host died mid-build")

    with pytest.raises(RuntimeError):
        _build(out_root, wheel_builder=crash)

    staging = [p for p in out_root.iterdir() if p.name.startswith(".staging-")]
    assert staging, "the failure record stays in staging for a post-mortem"
    state = json.loads((staging[0] / BUILD_STATE_FILENAME).read_text())
    assert state["state"] == "failed" and "RuntimeError" in state["reason"]
    # Never promoted to the build id, so it cannot be staged by the installer.
    assert not any(p.is_dir() and not p.name.startswith(".") for p in out_root.iterdir())
