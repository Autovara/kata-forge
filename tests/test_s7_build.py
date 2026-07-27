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
from kata_forge.cli import _derive_spec, build_parser
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
    kwargs = {
        "output_root": out_root,
        "spec": _spec(),
        "repo": GOOD,
        "kata_rev": "k1",
        "kata_bot_rev": "b1",
        "kata_forge_rev": "f1",
        "kata_tree_hash": "a" * 64,
        "git_runner": ScriptedGit(FREE_SOURCE),
        "wheel_builder": fake_wheel,
        "vendor_closure_files": 1,
        "vendor_files": ["scorer.py"],
        "source_repo": "Autovara/kata",
    }
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


# ---- command identity -----------------------------------------------------------------------
def test_build_repo_requires_an_explicit_subnet_identity():
    args = build_parser().parse_args(["build", "--repo", GOOD])
    with pytest.raises(ValueError, match="cannot securely reveal its subnet"):
        _derive_spec(args)


def test_build_repo_and_subnet_derive_a_consistent_lane_spec():
    args = build_parser().parse_args(["build", "--repo", GOOD, "--subnet", "44"])
    spec = _derive_spec(args)
    assert spec.subnet_number == 44
    assert spec.pack == "sn44__poker44"
    assert spec.evaluator_id == "sn44_poker44"


def test_build_rejects_an_invalid_source_repo_before_fetch(out_root):
    with pytest.raises(BuildError, match="owner/repo"):
        _build(out_root, source_repo="Autovara/repo with spaces")


def test_low_level_build_cannot_bypass_spec_validation(out_root):
    invalid = SubnetSpec(
        subnet_number=44,
        pack="sn44__" + "x" * 35,
        evaluator_id="sn44_x",
    )
    with pytest.raises(ValueError, match="lane id"):
        _build(out_root, spec=invalid)


# ---- build identity --------------------------------------------------------------------------
def test_the_build_id_is_the_hash_of_its_inputs():
    base = BuildInputs(source_url=GOOD, source_commit=SHA, kata_rev="k", kata_bot_rev="b",
                       kata_forge_rev="f")
    assert base.build_id() == BuildInputs(**base.canonical()).build_id()  # deterministic
    for field, value in [("source_commit", "f" * 40), ("kata_rev", "k2"), ("attempt_nonce", "2")]:
        changed = BuildInputs(**{**base.canonical(), field: value})
        assert changed.build_id() != base.build_id(), f"{field} must change the build id"


def test_every_declared_build_input_changes_the_identity():
    base = BuildInputs(
        source_url=GOOD,
        source_commit=SHA,
        kata_rev="k",
        kata_bot_rev="b",
        kata_forge_rev="f",
        subnet_id=44,
        pack="sn44__poker44",
        evaluator="sn44_poker44",
        mode="miner",
        source_repo="Autovara/kata",
        kata_tree_hash="a" * 64,
        plugin_contract_version=1,
        plugin_source_sha256="plugin-a",
        decision_inputs_sha256="decision-a",
        build_tools_sha256="tools-a",
        ai_config_sha256="ai-a",
    )
    replacements = {
        "source_url": "https://github.com/Autovara/other",
        "source_commit": "f" * 40,
        "kata_rev": "k2",
        "kata_bot_rev": "b2",
        "kata_forge_rev": "f2",
        "subnet_id": 45,
        "pack": "sn44__other",
        "evaluator": "sn44_other",
        "mode": "validator",
        "source_repo": "Autovara/other",
        "kata_tree_hash": "b" * 64,
        "plugin_contract_version": 2,
        "plugin_source_sha256": "plugin-b",
        "decision_inputs_sha256": "decision-b",
        "build_tools_sha256": "tools-b",
        "ai_config_sha256": "ai-b",
        "policy_version": "s7.next",
        "attempt_nonce": "2",
    }
    for field, replacement in replacements.items():
        changed = BuildInputs(**{**base.canonical(), field: replacement})
        assert changed.build_id() != base.build_id(), f"{field} is missing from build identity"


def test_the_build_id_covers_every_pinned_revision():
    canonical = BuildInputs(source_url=GOOD, source_commit=SHA, kata_rev="k", kata_bot_rev="b",
                            kata_forge_rev="f").canonical()
    assert set(canonical) == {
        "source_url", "source_commit", "kata_rev", "kata_bot_rev", "kata_forge_rev",
        "subnet_id", "pack", "evaluator", "mode", "source_repo", "kata_tree_hash",
        "plugin_contract_version", "plugin_source_sha256", "decision_inputs_sha256",
        "build_tools_sha256", "ai_config_sha256", "policy_version", "attempt_nonce",
    }


# ---- the happy path --------------------------------------------------------------------------
def _completed_plugin(tmp_path):
    """A plugin with every subnet-specific method written, as a human would finish it."""
    tree = tmp_path / "completed" / "kata-sn44" / "kata_sn44"
    tree.mkdir(parents=True, exist_ok=True)
    (tree.parent / "pyproject.toml").write_text(
        "[project]\nname = 'kata-sn44'\nversion = '0.1.0'\n\n"
        '[project.entry-points."kata.subnets"]\n'
        "sn44 = 'kata_sn44:PLUGIN'\n", encoding="utf-8")
    (tree / "__init__.py").write_text("from kata_sn44.plugin import PLUGIN\n", encoding="utf-8")
    (tree / "plugin.py").write_text(
        "UNRESOLVED_METHODS = ()\n\n\nclass P:\n    evaluator_id = 'sn44_poker44'\n\n\n"
        "PLUGIN = P()\n", encoding="utf-8")
    return tree.parent


def test_a_scaffolded_build_is_verified_but_not_installable(out_root):
    """A scaffold's subnet-specific methods are unwritten. The build still completes and is
    reviewable -- that is an honest UNRESOLVED outcome -- but it must never be installable."""
    result = _build(out_root)

    assert result.state == "verified" and result.mode == VENDOR
    assert not result.installable
    assert result.unresolved_methods == ["benchmark_identity", "run_candidate",
                                         "sample_problems", "score"]
    state = json.loads((result.bundle_dir / BUILD_STATE_FILENAME).read_text())
    assert state["unresolved_methods"] == result.unresolved_methods


def test_vendor_count_without_exact_files_is_refused(out_root):
    result = _build(out_root, vendor_files=[])

    assert result.state == "refused"
    assert result.mode == "REFUSE"
    assert "exact vendor file list" in result.reason
    assert not (result.bundle_dir / MANIFEST_FILENAME).exists()


def test_a_completed_plugin_emits_an_installable_bundle(out_root, tmp_path):
    result = _build(out_root, plugin_source=_completed_plugin(tmp_path))

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
    assert len(manifest["abi"]["plugin_rev"]) == 64
    assert manifest["abi"]["plugin_rev"] != "f1", \
        "plugin_rev must identify plugin bytes, not the forge revision"
    # A VENDOR lane declares no upstream pin -- kata-bot forbids it, because the vendored copy is
    # the single source of truth and a second pin would drift.
    assert manifest["registry_change"]["lane"]["integration_mode"] == "vendor"
    assert "upstream_commit" not in manifest["registry_change"]["lane"]


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
    assert not second.installable, "reusing an unresolved scaffold must not upgrade its status"
    assert second.unresolved_methods == first.unresolved_methods


def test_plugin_source_bytes_change_the_build_id(out_root, tmp_path):
    plugin = _completed_plugin(tmp_path)
    first = _build(out_root, plugin_source=plugin)
    (plugin / "kata_sn44" / "plugin.py").write_text(
        (plugin / "kata_sn44" / "plugin.py").read_text() + "\nCHANGED = True\n",
        encoding="utf-8",
    )
    second = _build(out_root, plugin_source=plugin)
    assert second.build_id != first.build_id


def test_decision_evidence_and_lane_identity_change_the_build_id(out_root):
    first = _build(out_root)
    changed_evidence = _build(out_root, vendor_entangled=["bittensor"])
    changed_source_repo = _build(out_root, source_repo="Autovara/other")
    changed_spec = _build(
        out_root,
        spec=SubnetSpec(
            subnet_number=45,
            pack="sn45__poker44",
            evaluator_id="sn45_poker44",
            mode="miner",
            name="poker44",
        ),
    )
    assert len({
        first.build_id,
        changed_evidence.build_id,
        changed_source_repo.build_id,
        changed_spec.build_id,
    }) == 4


def test_ai_provider_model_and_budget_change_the_build_id(out_root, monkeypatch):
    first = _build(out_root)
    monkeypatch.setenv("KATA_FORGE_LLM", "provider-b")
    monkeypatch.setenv("KATA_FORGE_AI_MODEL", "model-b")
    monkeypatch.setenv("KATA_FORGE_AI_MAX_ATTEMPTS", "2")
    second = _build(out_root)
    assert second.build_id != first.build_id


def test_a_tampered_verified_build_is_never_reused(out_root):
    first = _build(out_root)
    (first.bundle_dir / SBOM_FILENAME).write_text('{"tampered":true}\n', encoding="utf-8")
    with pytest.raises(BuildError, match="differs from its manifest"):
        _build(out_root)


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


def test_a_refused_result_is_retained_but_not_reused_without_a_new_attempt(out_root):
    source = ScriptedGit({**FREE_SOURCE, "requirements.txt": "openai\n"})
    first = _build(out_root, git_runner=source)
    assert first.state == "refused"
    with pytest.raises(BuildError, match="has no verifiable release manifest"):
        _build(out_root, git_runner=source)


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


@pytest.mark.parametrize("outcome", ["failed", "not-run"])
def test_a_smoke_check_that_did_not_pass_refuses_the_bundle(out_root, monkeypatch, outcome):
    import kata_forge.build as build_module

    monkeypatch.setattr(build_module, "_run_plugin_smoke_check", lambda *_args: outcome)
    result = _build(out_root)
    assert result.state == "refused"
    assert result.forge_verification == outcome
    assert result.conformance == "pending-installer"
    assert not result.installable
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
    # A missing compartment is a refusal, never a verified build. Runtime conformance belongs to
    # the trusted installer and is not falsely recorded as already passed.
    assert state["forge_verification"] == "passed"
    assert state["conformance"] == "pending-installer"
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


# ---- the draft loop closes the UNRESOLVED gap ----------------------------------------------------
_DRAFTER_MODULE = '''\
"""A deterministic stand-in drafter: no model, no network, no spend."""
_BODIES = {
    "sample_problems": "return [{'id': i} for i in range(3)]",
    "benchmark_identity": "return 'synthetic-' + str(len(problems))",
    "run_candidate": "return {'answers': [0] * len(problems)}",
    "score": "return {'comparable': float(len(raw['answers'])), 'passed': True}",
}


def draft(method, prompt):
    return _BODIES.get(method, "raise NotImplementedError('no draft')")
'''


@pytest.fixture
def configured_drafter(tmp_path, monkeypatch):
    """Point the build at a deterministic drafter with every AI bound configured."""
    for name, value in {
        "KATA_FORGE_AI_MAX_WALL_SECONDS": "600",
        "KATA_FORGE_AI_MAX_INPUT_BYTES": "200000",
        "KATA_FORGE_AI_MAX_OUTPUT_TOKENS": "4000",
        "KATA_FORGE_AI_MAX_ATTEMPTS": "3",
        "KATA_FORGE_LLM": "demo",
    }.items():
        monkeypatch.setenv(name, value)
    bodies = {
        "sample_problems": "return [{'id': i} for i in range(3)]",
        "benchmark_identity": "return 'synthetic-' + str(len(problems))",
        "run_candidate": "return {'answers': [0] * len(problems)}",
        "score": "return {'comparable': float(len(raw['answers'])), 'passed': True}",
    }
    return lambda method, _prompt: bodies.get(method, "raise NotImplementedError('no draft')")


def test_the_draft_loop_resolves_every_method_and_makes_the_bundle_installable(
        out_root, configured_drafter):
    """The gap that made `build` produce a bundle the installer refused: with drafting configured,
    every scaffolded method is drafted, verified and spliced, and the result is installable."""
    result = _build(
        out_root,
        drafter=configured_drafter,
        draft_verifier=lambda _tree: (True, ""),
    )

    assert result.unresolved_methods == [] and result.installable
    draft = json.loads((result.bundle_dir / "ai-draft.json").read_text())
    assert sorted(draft["drafted"]) == ["benchmark_identity", "run_candidate",
                                        "sample_problems", "score"]
    # The plugin no longer RAISES from the methods a challenge calls. (The module docstring still
    # mentions NotImplementedError while describing the scaffold, so match the statement, not the
    # word.)
    plugin = next((result.bundle_dir / "plugin").rglob("plugin.py")).read_text()
    assert "raise NotImplementedError" not in plugin


def test_drafting_writes_redacted_provenance(out_root, configured_drafter):
    result = _build(
        out_root,
        drafter=configured_drafter,
        draft_verifier=lambda _tree: (True, ""),
    )
    usage = json.loads((result.bundle_dir / "ai-usage.json").read_text())
    assert usage["build_id"] == result.build_id
    assert [a["result"] for a in usage["attempts"]] == ["passed"] * 4
    assert usage["limits"]["max_attempts"] == 3
    # Counts and hashes only -- no prompt text, no source, no credential.
    assert "prompt" not in json.dumps(usage).lower().replace("prompt_template_sha256", "")


def test_drafter_command_path_cannot_escape_usr_with_dotdot(monkeypatch):
    from kata_forge.build import _load_drafter

    monkeypatch.setenv(
        "KATA_FORGE_DRAFTER_ARGV_JSON",
        '["/usr/../tmp/attacker-controlled-drafter"]',
    )

    with pytest.raises(BuildError, match="does not resolve|must resolve"):
        _load_drafter()


def test_a_drafter_that_never_succeeds_leaves_an_honest_unresolved_build(out_root, monkeypatch,
                                                                        tmp_path):
    for name, value in {"KATA_FORGE_AI_MAX_WALL_SECONDS": "600",
                        "KATA_FORGE_AI_MAX_INPUT_BYTES": "200000",
                        "KATA_FORGE_AI_MAX_OUTPUT_TOKENS": "4000",
                        "KATA_FORGE_AI_MAX_ATTEMPTS": "2"}.items():
        monkeypatch.setenv(name, value)

    result = _build(
        out_root,
        drafter=lambda _method, _prompt: "def broken(:",
        draft_verifier=lambda _tree: (False, "authoritative fixture failed"),
    )
    assert result.unresolved_methods and not result.installable
    assert result.state == "verified"  # the BUILD completed; the methods did not


def test_ai_is_not_called_without_an_authoritative_subnet_verifier(
        out_root, configured_drafter):
    calls = []

    def must_not_run(method, prompt):
        calls.append((method, prompt))
        return "return None"

    result = _build(out_root, drafter=must_not_run)
    assert calls == []
    assert result.unresolved_methods
    assert not result.installable
