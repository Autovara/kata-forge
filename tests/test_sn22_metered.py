"""SN22-0: the gated metered integration policy.

SN22 (Desearch) is the first subnet whose validator is genuinely NOT free — the real upstream at the
pinned commit surveys as ``METERED`` / ``NEEDS-KEYS`` with paid providers apify, openai and
scrapingdog. Onboarding it therefore has to be possible without dismantling the free-by-default gate
that protects every other subnet.

These tests pin the four properties that make that safe, and one wiring property:

1. free stays the default (no policy => the SN22 survey still REFUSEs);
2. names, never values (a policy carrying a credential value is refused);
3. provider-bound (an approval must cover every paid provider actually found);
4. bounded (an approval with no per-day limit is not an approval);
5. the approval is a BUILD INPUT — it changes the build id and lands in the manifest.
"""
from __future__ import annotations

import json

import pytest

from kata_forge.decision import REFUSE, VENDOR, DecisionInputs, decide
from kata_forge.metered import (
    KNOWN_DIMENSIONS,
    MeteredPolicyError,
    load_metered_policy,
    parse_metered_policy,
)

#: What the real SN22 validator surveys as at the pinned commit — the case this whole phase exists
#: for. Kept as data so the gate is tested against reality, not a convenient fiction.
SN22_PAID_PROVIDERS = ["apify", "openai", "scrapingdog"]
SN22_CREDENTIAL_NAMES = [
    "APIFY_API_KEY", "CHUTES_API_KEY", "OPENAI_API_KEY", "SCRAPINGDOG_API_KEY",
]


def _policy(**overrides) -> dict:
    document = {
        "schema_version": 1,
        "subnet_id": 22,
        "approved_by": "reviewer-x",
        "approved_at": "2026-07-27T00:00:00Z",
        "providers": list(SN22_PAID_PROVIDERS),
        "credential_names": list(SN22_CREDENTIAL_NAMES),
        "daily_limits": {"inference_calls": 500, "spend_usd": 25.0, "data_api_calls": 2000},
        "notes": "SN22 activation, phase SN22-0",
    }
    document.update(overrides)
    return document


def _sn22_inputs(**overrides) -> DecisionInputs:
    """A decision input matching the REAL SN22 survey: metered, needs keys, vendorable scorer."""
    base = {
        "source_url": "https://github.com/Desearch-ai/subnet-22",
        "source_commit": "bea9712f58a5fc01c57ec441ce279499529d8bf6",
        "dep_verdict": "NEEDS-KEYS",
        "cost_class": "METERED",
        "needs_gpu": False,
        "license": {"spdx": "MIT", "vendor_allowed": True},
        "vendor_closure_files": 1,
        "vendor_files": ["scoring.py"],
        "paid_providers": list(SN22_PAID_PROVIDERS),
    }
    base.update(overrides)
    return DecisionInputs(**base)


# ---- property 1: free stays the default ----------------------------------------------------------
def test_sn22_refuses_with_no_policy_at_all() -> None:
    """The locked default. Nothing about SN22-0 makes a paid validator onboardable by accident."""
    decision = decide(_sn22_inputs())
    assert decision.mode == REFUSE
    assert any("not free" in reason for reason in decision.reasons)


def test_a_free_validator_never_consults_the_metered_gate() -> None:
    decision = decide(_sn22_inputs(dep_verdict="FREE", cost_class="FREE", paid_providers=[]))
    assert decision.mode == VENDOR


def test_no_environment_variable_can_enable_metered(monkeypatch) -> None:
    """There is deliberately no env escape hatch. Anything plausible a reader might try must not work."""
    for name in ("KATA_FORGE_ALLOW_METERED", "KATA_FORGE_ALLOW_PAID", "ALLOW_METERED",
                 "KATA_FORGE_METERED_POLICY"):
        monkeypatch.setenv(name, "1")
    assert decide(_sn22_inputs()).mode == REFUSE


# ---- property 2: names, never values -------------------------------------------------------------
@pytest.mark.parametrize("value", [
    "ghp_abcdefghijklmnopqrstuvwxyz0123456789",
    "sk-abcdefghijklmnopqrstuvwxyz",
    "apify_api_abcdefghijklmnopqrstuv",
    "AKIAIOSFODNN7EXAMPLE",
    "-----BEGIN RSA PRIVATE KEY-----",
])
def test_a_policy_carrying_a_credential_value_is_refused(value: str) -> None:
    """A policy is reviewed, committed and copied around; it must stay safe to do all three with."""
    with pytest.raises(MeteredPolicyError, match="credential VALUE"):
        parse_metered_policy(_policy(notes=f"key is {value}"))


def test_a_credential_value_hidden_deep_in_the_document_is_still_refused() -> None:
    with pytest.raises(MeteredPolicyError, match="credential VALUE"):
        parse_metered_policy(_policy(providers=["apify", "ghp_abcdefghijklmnopqrstuvwxyz012345"]))


def test_credential_names_must_look_like_names() -> None:
    with pytest.raises(MeteredPolicyError, match="environment variable NAME"):
        parse_metered_policy(_policy(credential_names=["apify api key"]))


# ---- property 3: provider-bound ------------------------------------------------------------------
def test_an_approval_must_cover_every_provider_the_survey_found() -> None:
    """The approval must cover REALITY, not only what the reviewer expected to find."""
    narrow = _policy(providers=["openai"])
    decision = decide(_sn22_inputs(metered_policy=narrow))
    assert decision.mode == REFUSE
    assert any("apify" in r and "scrapingdog" in r for r in decision.reasons)


def test_upstream_adding_a_provider_invalidates_an_existing_approval() -> None:
    """The failure this closes: upstream adds a paid dependency and rides the old approval silently."""
    approved = _policy()
    assert decide(_sn22_inputs(metered_policy=approved)).mode == VENDOR
    widened = _sn22_inputs(metered_policy=approved,
                           paid_providers=[*SN22_PAID_PROVIDERS, "anthropic"])
    later = decide(widened)
    assert later.mode == REFUSE
    assert any("anthropic" in reason for reason in later.reasons)


# ---- property 4: bounded -------------------------------------------------------------------------
def test_an_approval_with_no_daily_limit_is_not_an_approval() -> None:
    with pytest.raises(MeteredPolicyError, match="blank cheque"):
        parse_metered_policy(_policy(daily_limits={}))


@pytest.mark.parametrize("limits", [
    {"inference_calls": 0},
    {"inference_calls": -1},
    {"spend_usd": True},
    {"spend_usd": "lots"},
])
def test_a_limit_that_does_not_bound_anything_is_refused(limits: dict) -> None:
    with pytest.raises(MeteredPolicyError, match="positive number"):
        parse_metered_policy(_policy(daily_limits=limits))


def test_an_unknown_budget_dimension_is_refused() -> None:
    """A typo'd dimension would silently bound nothing kata-bot ever meters."""
    with pytest.raises(MeteredPolicyError, match="unknown budget dimension"):
        parse_metered_policy(_policy(daily_limits={"inference_call": 10}))


def test_every_declared_dimension_is_one_kata_bot_actually_meters() -> None:
    for dimension in _policy()["daily_limits"]:
        assert dimension in KNOWN_DIMENSIONS


# ---- the approval itself must be well-formed -----------------------------------------------------
@pytest.mark.parametrize("overrides, match", [
    ({"schema_version": 2}, "schema_version"),
    ({"subnet_id": 0}, "positive int"),
    ({"subnet_id": True}, "positive int"),
    ({"approved_by": ""}, "approved_by"),
    ({"approved_at": ""}, "approved_at"),
    ({"providers": []}, "at least one paid provider"),
    ({"credential_names": []}, "credential NAMES"),
])
def test_a_malformed_policy_is_refused(overrides: dict, match: str) -> None:
    with pytest.raises(MeteredPolicyError, match=match):
        parse_metered_policy(_policy(**overrides))


def test_a_non_object_policy_is_refused() -> None:
    with pytest.raises(MeteredPolicyError, match="JSON object"):
        parse_metered_policy(["not", "an", "object"])


def test_load_refuses_unreadable_and_invalid_json(tmp_path) -> None:
    with pytest.raises(MeteredPolicyError, match="cannot read"):
        load_metered_policy(tmp_path / "absent.json")
    bad = tmp_path / "bad.json"
    bad.write_text("{not json", encoding="utf-8")
    with pytest.raises(MeteredPolicyError, match="invalid JSON"):
        load_metered_policy(bad)


def test_a_valid_policy_round_trips_through_a_file(tmp_path) -> None:
    path = tmp_path / "sn22.json"
    path.write_text(json.dumps(_policy()), encoding="utf-8")
    policy = load_metered_policy(path)
    assert policy.subnet_id == 22
    assert policy.covers(SN22_PAID_PROVIDERS) == (True, "")
    assert policy.as_evidence()["providers"] == sorted(SN22_PAID_PROVIDERS)


def test_evidence_carries_names_and_bounds_only() -> None:
    evidence = parse_metered_policy(_policy()).as_evidence()
    assert set(evidence) == {"schema_version", "subnet_id", "approved_by", "approved_at",
                             "providers", "credential_names", "daily_limits", "notes"}
    assert evidence["credential_names"] == sorted(SN22_CREDENTIAL_NAMES)


# ---- the gate is precedence-correct --------------------------------------------------------------
def test_an_embedded_credential_still_refuses_even_with_a_valid_approval() -> None:
    """Step 1 beats step 2: a leaked credential must refuse before the cost question is reached."""
    decision = decide(_sn22_inputs(
        metered_policy=_policy(),
        embedded_secrets=[{"kind": "openai_key", "file": "x.py", "line": 3}],
    ))
    assert decision.mode == REFUSE
    assert any("embedded credential" in reason for reason in decision.reasons)


def test_a_gpu_requirement_still_refuses_even_with_a_valid_approval() -> None:
    decision = decide(_sn22_inputs(metered_policy=_policy(), needs_gpu=True))
    assert decision.mode == REFUSE
    assert any("GPU" in reason for reason in decision.reasons)


def test_a_malformed_approval_refuses_rather_than_being_ignored() -> None:
    """Fail closed: an unparseable approval must not degrade to 'no approval supplied, carry on'."""
    decision = decide(_sn22_inputs(metered_policy={"schema_version": 99}))
    assert decision.mode == REFUSE
    assert any("not valid" in reason for reason in decision.reasons)


def test_an_approved_sn22_records_its_approval_in_the_decision_evidence() -> None:
    decision = decide(_sn22_inputs(metered_policy=_policy()))
    assert decision.mode == VENDOR
    cost = decision.evidence["cost"]
    assert cost["paid_providers"] == sorted(SN22_PAID_PROVIDERS)
    assert cost["metered_policy"]["approved_by"] == "reviewer-x"
    assert cost["metered_policy"]["daily_limits"]["spend_usd"] == 25.0


# ---- property 5: the approval is a BUILD INPUT ---------------------------------------------------
# These exercise the real ``build`` chain with a scripted git runner and an injected wheel builder,
# using a source that genuinely surveys as METERED / NEEDS-KEYS (openai + apify-client).
MIT_TEXT = ("MIT License\n\nPermission is hereby granted, free of charge, to any person obtaining a "
            "copy\n")
PAID_SOURCE = {
    "LICENSE": MIT_TEXT,
    "requirements.txt": "openai\napify-client\n",
    "scorer.py": "def score(x): return x\n",
}
#: What that fixture actually surveys as. Asserted in a test below, not assumed.
PAID_SOURCE_PROVIDERS = ["apify", "openai"]


def _paid_policy(**overrides) -> dict:
    return _policy(providers=list(PAID_SOURCE_PROVIDERS),
                   credential_names=["APIFY_API_KEY", "OPENAI_API_KEY"], **overrides)


@pytest.fixture
def paid_build(tmp_path):
    """A ``build(...)`` bound to a metered source, parameterizable per test."""
    from kata_forge.build import build
    from kata_forge.spec import SubnetSpec
    from tests.test_s7_build import ScriptedGit, fake_wheel

    out_root = tmp_path / "out"
    out_root.mkdir(mode=0o700)

    def run(**over):
        kwargs = {
            "output_root": out_root,
            "spec": SubnetSpec(subnet_number=22, pack="sn22__desearch",
                               evaluator_id="sn22_desearch", mode="miner", name="desearch"),
            "repo": "https://github.com/Desearch-ai/subnet-22",
            "kata_rev": "k1", "kata_bot_rev": "b1", "kata_forge_rev": "f1",
            "kata_tree_hash": "a" * 64,
            "git_runner": ScriptedGit(PAID_SOURCE),
            "wheel_builder": fake_wheel,
            "vendor_closure_files": 1,
            "vendor_files": ["scorer.py"],
            "source_repo": "Autovara/kata",
        }
        kwargs.update(over)
        return build(**kwargs)

    return run


def _write_policy(tmp_path, document: dict, name: str = "sn22.json"):
    path = tmp_path / name
    path.write_text(json.dumps(document), encoding="utf-8")
    return path


def test_the_fixture_really_is_metered(tmp_path) -> None:
    """Guards the tests below: if this source ever stopped being paid, they would prove nothing."""
    from kata_forge.cost import estimate_cost
    from kata_forge.deps import classify_repo

    source = tmp_path / "src"
    source.mkdir()
    for rel, text in PAID_SOURCE.items():
        (source / rel).write_text(text, encoding="utf-8")
    deps = classify_repo(source)
    cost = estimate_cost(source, deps=deps)
    assert deps.verdict == "NEEDS-KEYS"
    assert cost.cost_class == "METERED"
    assert sorted(cost.paid_providers) == PAID_SOURCE_PROVIDERS


def test_a_metered_build_without_an_approval_refuses(paid_build) -> None:
    result = paid_build()
    assert result.state == "refused"
    assert "not free" in result.reason


def test_an_approved_metered_build_emits_the_declaration(paid_build, tmp_path) -> None:
    from kata_forge.build import MANIFEST_FILENAME

    policy_path = _write_policy(tmp_path, _paid_policy())
    result = paid_build(metered_policy_path=policy_path)
    assert result.state == "verified"

    manifest = json.loads((result.bundle_dir / MANIFEST_FILENAME).read_text(encoding="utf-8"))
    metered = manifest["integration"]["metered"]
    assert metered["subnet_id"] == 22
    assert metered["providers"] == PAID_SOURCE_PROVIDERS
    assert metered["observed_providers"] == PAID_SOURCE_PROVIDERS
    assert metered["cost_class"] == "METERED"
    assert metered["dep_verdict"] == "NEEDS-KEYS"
    assert metered["daily_limits"]["spend_usd"] == 25.0
    # The manifest is hashed into the bundle digest, so the declaration is immutable and covered by
    # the reviewer's approval rather than being loose metadata beside it.
    assert MANIFEST_FILENAME not in manifest["tree_manifest"]
    assert manifest["bundle_digest"]


def test_a_free_build_emits_no_metered_declaration(tmp_path) -> None:
    """A free lane must not carry a paid declaration -- the installer reads it as a spending claim."""
    from kata_forge.build import MANIFEST_FILENAME
    from tests.test_s7_build import FREE_SOURCE, ScriptedGit, _build, out_root  # noqa: F401

    root = tmp_path / "out"
    root.mkdir(mode=0o700)
    result = _build(root, git_runner=ScriptedGit(FREE_SOURCE))
    manifest = json.loads((result.bundle_dir / MANIFEST_FILENAME).read_text(encoding="utf-8"))
    assert "metered" not in manifest["integration"]


def test_changing_the_approved_limits_changes_the_build_id(paid_build, tmp_path) -> None:
    """An approval is a build input. Re-approving different ceilings must not silently reuse the
    bundle that was reviewed under the old ones."""
    first = paid_build(metered_policy_path=_write_policy(tmp_path, _paid_policy(), "a.json"))
    raised = _paid_policy(daily_limits={"inference_calls": 500, "spend_usd": 250.0,
                                        "data_api_calls": 2000})
    second = paid_build(metered_policy_path=_write_policy(tmp_path, raised, "b.json"))
    assert first.state == second.state == "verified"
    assert first.build_id != second.build_id
    assert not second.reused


def test_an_identical_approval_still_reuses_the_build(paid_build, tmp_path) -> None:
    path = _write_policy(tmp_path, _paid_policy())
    first = paid_build(metered_policy_path=path)
    second = paid_build(metered_policy_path=path)
    assert second.build_id == first.build_id
    assert second.reused


def test_an_approval_for_another_subnet_is_not_transferable(paid_build, tmp_path) -> None:
    from kata_forge.build import BuildError

    path = _write_policy(tmp_path, _paid_policy(subnet_id=60))
    with pytest.raises(BuildError, match="not transferable"):
        paid_build(metered_policy_path=path)


def test_a_malformed_policy_file_stops_the_build_in_preflight(paid_build, tmp_path) -> None:
    """Refuse before anything is fetched: a bad approval is the cheapest possible refusal."""
    path = _write_policy(tmp_path, _paid_policy(daily_limits={}))
    with pytest.raises(MeteredPolicyError, match="blank cheque"):
        paid_build(metered_policy_path=path)


def test_the_build_cli_exposes_the_flag_and_nothing_enables_it_by_default() -> None:
    from kata_forge.cli import build_parser

    parser = build_parser()
    args = parser.parse_args(["build", "--repo", "https://github.com/Desearch-ai/subnet-22",
                              "--subnet", "22", "--out", "/tmp/x"])
    assert args.metered_policy is None
    with_policy = parser.parse_args(["build", "--repo", "https://github.com/Desearch-ai/subnet-22",
                                     "--subnet", "22", "--out", "/tmp/x",
                                     "--metered-policy", "/tmp/sn22.json"])
    assert with_policy.metered_policy == "/tmp/sn22.json"


# ---- "is this paid?" is asked ONCE ---------------------------------------------------------------
def test_a_low_cost_validator_with_a_paid_provider_still_needs_an_approval() -> None:
    """A paid provider inferred from a credential NAME rather than a dependency lands at LOW/FREE.
    Low spending is still spending, so it must not walk past the gate."""
    from kata_forge.decision import requires_metered_approval

    assert requires_metered_approval("LOW", "FREE", ["scrapingdog"])
    decision = decide(_sn22_inputs(cost_class="LOW", dep_verdict="FREE",
                                   paid_providers=["scrapingdog"]))
    assert decision.mode == REFUSE
    assert any("not free" in reason for reason in decision.reasons)


def test_a_genuinely_free_survey_needs_nothing() -> None:
    from kata_forge.decision import requires_metered_approval

    assert not requires_metered_approval("FREE", "FREE", [])


def test_the_gate_and_the_manifest_declaration_share_one_predicate() -> None:
    """Two copies of 'is this paid?' that drift produce a lane the gate calls paid and the manifest
    calls free. Pin that build.py derives its declaration from the decision module's predicate."""
    import kata_forge.build as build_module
    from kata_forge.decision import requires_metered_approval

    assert build_module.requires_metered_approval is requires_metered_approval
