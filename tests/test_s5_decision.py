"""S5: three-outcome decision, license gate, redaction, and the executed parity fixture (plan 5/7).

The governing rule under test: the mode is selected by deterministic policy over measurable evidence,
never by a model, and never as a half-working compromise.
"""
from __future__ import annotations

import json

import pytest

from kata_forge.decision import (
    CLONE,
    MAX_VENDOR_FILES,
    POLICY_VERSION,
    REFUSE,
    VENDOR,
    DecisionInputs,
    decide,
    decision_document,
    write_decision_record,
)
from kata_forge.license_gate import detect_license
from kata_forge.parity import ParityCase, ParityResult, run_parity_fixture
from kata_forge.redaction import REDACTED, redact, scan_embedded_secrets

FULL_SHA = "c" * 40
MIT = "MIT License\n\nPermission is hereby granted, free of charge, to any person obtaining a copy\n"
GPL = "GNU GENERAL PUBLIC LICENSE\nVersion 3, 29 June 2007\n"


def _passing_parity(cases=2):
    return ParityResult(executed=True, matched=True, cases_run=cases).as_evidence()


def _inputs(**over):
    base = dict(
        source_url="https://github.com/o/r",
        source_commit=FULL_SHA,
        dep_verdict="FREE",
        cost_class="FREE",
        needs_gpu=False,
        license={"spdx": "MIT", "vendor_allowed": True, "reason": "permissive"},
    )
    base.update(over)
    return DecisionInputs(**base)


# ---- the plan's named acceptance cases -----------------------------------------------------------
def test_a_pure_shaped_free_scorer_yields_vendor():
    """SN126-shaped: a tiny pure closure, permissive licence, no entanglement."""
    decision = decide(_inputs(vendor_closure_files=2, vendor_entangled=[]))
    assert decision.mode == VENDOR
    assert "closure 2 file(s)" in " ".join(decision.reasons)


def test_an_entangled_free_validator_with_executed_parity_yields_clone():
    """SN60-shaped: needs its own repo and runtime, but a parity fixture actually ran and matched."""
    decision = decide(_inputs(vendor_closure_files=40,
                              vendor_entangled=["docker", "bittensor"],
                              parity=_passing_parity(cases=3)))
    assert decision.mode == CLONE
    assert "executed 3 case(s) and matched" in " ".join(decision.reasons)


def test_an_unsatisfiable_synthetic_yields_refuse():
    """Neither a vendor proof nor an executed parity fixture: REFUSE, never a half-working adapter."""
    decision = decide(_inputs(vendor_closure_files=99, vendor_entangled=["docker"], parity={}))
    assert decision.mode == REFUSE
    assert "half-working adapter" in " ".join(decision.reasons)


# ---- fixed precedence ----------------------------------------------------------------------------
def test_an_embedded_credential_refuses_before_anything_else():
    """Must refuse BEFORE any AI input: drafting would transmit the credential to a model provider.
    Even a perfect vendor proof must not outrank it."""
    decision = decide(_inputs(
        vendor_closure_files=1,
        embedded_secrets=[{"kind": "github-pat", "path": "a.py", "line": 3}],
    ))
    assert decision.mode == REFUSE
    assert "before any AI input" in " ".join(decision.reasons)


def test_an_unpinned_source_refuses():
    for bad in ("", "abc123", "a" * 39):
        decision = decide(_inputs(source_commit=bad, vendor_closure_files=1))
        assert decision.mode == REFUSE
        assert "40-character sha" in " ".join(decision.reasons)


@pytest.mark.parametrize("over", [
    {"cost_class": "METERED"},
    {"dep_verdict": "NEEDS-KEYS"},
])
def test_a_paid_validator_refuses_even_with_passing_parity(over):
    """The free gate outranks a parity proof: a metered subnet must not be cloned into production."""
    decision = decide(_inputs(parity=_passing_parity(), **over))
    assert decision.mode == REFUSE
    assert "not free" in " ".join(decision.reasons)


def test_gpu_refuses_unless_explicitly_allowed():
    assert decide(_inputs(needs_gpu=True, vendor_closure_files=1)).mode == REFUSE
    assert decide(_inputs(needs_gpu=True, allow_gpu=True, vendor_closure_files=1)).mode == VENDOR


def test_license_blocks_vendor_but_not_clone():
    """An unvendorable licence is a reason not to COPY, not a reason to refuse outright: cloning at
    a pinned commit is not redistribution."""
    unvendorable = {"spdx": "GPL-3.0", "vendor_allowed": False, "reason": "copyleft"}
    assert decide(_inputs(vendor_closure_files=1, license=unvendorable)).mode == REFUSE
    decision = decide(_inputs(vendor_closure_files=1, license=unvendorable,
                              parity=_passing_parity()))
    assert decision.mode == CLONE


def test_a_closure_above_the_cap_is_not_vendorable():
    assert decide(_inputs(vendor_closure_files=MAX_VENDOR_FILES)).mode == VENDOR
    assert decide(_inputs(vendor_closure_files=MAX_VENDOR_FILES + 1)).mode == REFUSE


# ---- the parity fixture must have ACTUALLY executed ----------------------------------------------
@pytest.mark.parametrize("parity,why", [
    ({}, "absent"),
    ({"executed": False, "matched": True, "cases_run": 5}, "never ran but claims a match"),
    ({"executed": True, "matched": True, "cases_run": 0}, "ran zero cases"),
    ({"executed": True, "matched": False, "cases_run": 3}, "ran and disagreed"),
    ({"executed": True, "matched": True, "cases_run": 2,
      "mismatches": [{"case": "x"}]}, "matched flag contradicts its own mismatches"),
])
def test_clone_requires_a_genuinely_executed_matching_fixture(parity, why):
    decision = decide(_inputs(vendor_closure_files=99, vendor_entangled=["docker"], parity=parity))
    assert decision.mode == REFUSE, f"CLONE must not be selected when the fixture {why}"


def test_parity_runner_reports_execution_honestly():
    cases = [ParityCase("a", 1), ParityCase("b", 2)]
    same = run_parity_fixture(cases, upstream=lambda x: x * 2, adapter=lambda x: x * 2)
    assert same.qualifies_for_clone and same.cases_run == 2

    differ = run_parity_fixture(cases, upstream=lambda x: x * 2, adapter=lambda x: x * 3)
    assert differ.executed and not differ.matched and not differ.qualifies_for_clone
    assert differ.mismatches


def test_an_empty_fixture_is_not_a_pass():
    """Comparing nothing always 'matches' -- the trap this gate exists to close."""
    result = run_parity_fixture([], upstream=lambda x: x, adapter=lambda x: x)
    assert not result.executed and not result.qualifies_for_clone


@pytest.mark.parametrize("side", ["upstream", "adapter"])
def test_a_raising_side_is_a_failure_not_a_match(side):
    def boom(_payload):
        raise RuntimeError("import error")

    result = run_parity_fixture(
        [ParityCase("a", 1)],
        upstream=boom if side == "upstream" else (lambda x: x),
        adapter=boom if side == "adapter" else (lambda x: x),
    )
    assert result.executed and not result.qualifies_for_clone and side in (result.error or "")


def test_a_raising_comparator_is_not_a_match():
    def bad_compare(_a, _b):
        raise TypeError("not comparable")

    result = run_parity_fixture([ParityCase("a", 1)], upstream=lambda x: x, adapter=lambda x: x,
                                compare=bad_compare)
    assert not result.qualifies_for_clone


# ---- the decision record -------------------------------------------------------------------------
def test_every_outcome_writes_a_record_with_evidence(tmp_path):
    for inputs in (_inputs(vendor_closure_files=1),
                   _inputs(vendor_closure_files=99, vendor_entangled=["docker"],
                           parity=_passing_parity()),
                   _inputs(vendor_closure_files=99, parity={})):
        decision = decide(inputs)
        path = write_decision_record(tmp_path / f"{decision.mode}.json", decision)
        record = json.loads(path.read_text())
        assert record["mode"] == decision.mode
        assert record["policy_version"] == POLICY_VERSION
        assert record["reasons"], "a refusal must carry a precise reason, not an empty list"
        assert record["evidence"]["source"]["commit"] == FULL_SHA
        assert "license" in record["evidence"] and "parity" in record["evidence"]


def test_the_record_is_canonical_and_reproducible(tmp_path):
    decision = decide(_inputs(vendor_closure_files=1))
    first = write_decision_record(tmp_path / "a.json", decision).read_text()
    second = write_decision_record(tmp_path / "b.json", decision).read_text()
    assert first == second and first.endswith("\n")  # deterministic evidence


def test_a_credential_never_reaches_the_record(tmp_path):
    """Reporting a leak must not repeat it: the record is written to disk and read by tools that
    were never vetted to hold a live credential."""
    leaked = "ghp_" + "A" * 36
    decision = decide(_inputs(embedded_secrets=[
        {"kind": "github-pat", "path": "a.py", "line": 3, "preview": f"TOKEN = '{leaked}'"}]))
    body = json.dumps(decision_document(decision))
    assert leaked not in body and REDACTED in body


# ---- redaction + embedded-credential scan --------------------------------------------------------
@pytest.mark.parametrize("secret", [
    "ghp_" + "A" * 36,
    "github_pat_" + "B" * 62,
    "sk-" + "C" * 32,
    "AKIAIOSFODNN7EXAMPLE",
    "xoxb-123456789012-abcdefghijkl",
    "AIza" + "D" * 35,
])
def test_known_credential_formats_are_found_and_redacted(tmp_path, secret):
    (tmp_path / "config.py").write_text(f"TOKEN = '{secret}'\n", encoding="utf-8")
    findings = scan_embedded_secrets(tmp_path)
    assert findings, f"{secret[:8]}... should have been detected"
    assert findings[0].path == "config.py" and findings[0].line == 1
    assert secret not in findings[0].preview and REDACTED in findings[0].preview
    assert secret not in json.dumps(findings[0].as_evidence())


def test_a_private_key_block_is_found(tmp_path):
    (tmp_path / "id_rsa").write_text("-----BEGIN RSA PRIVATE KEY-----\nMIIE\n", encoding="utf-8")
    assert any(f.kind == "private-key-block" for f in scan_embedded_secrets(tmp_path))


def test_a_clean_repo_has_no_findings(tmp_path):
    (tmp_path / "main.py").write_text(
        "import os\nAPI = os.environ['OPENAI_API_KEY']\nSHA = 'a'*40\n", encoding="utf-8")
    # Reading a key from the environment is a REQUIREMENT, not a leak; a hex sha is not a credential.
    assert scan_embedded_secrets(tmp_path) == []


def test_vendored_and_generated_trees_are_skipped(tmp_path):
    vendor = tmp_path / "node_modules" / "pkg"
    vendor.mkdir(parents=True)
    (vendor / "x.js").write_text("var t='ghp_" + "A" * 36 + "'\n", encoding="utf-8")
    assert scan_embedded_secrets(tmp_path) == []


def test_redact_is_idempotent_and_leaves_ordinary_text_alone():
    assert redact("nothing to see") == "nothing to see"
    once = redact("k=ghp_" + "A" * 36)
    assert redact(once) == once == f"k={REDACTED}"


# ---- license gate --------------------------------------------------------------------------------
@pytest.mark.parametrize("text,spdx", [
    (MIT, "MIT"),
    ("Apache License\nVersion 2.0, January 2004\n", "Apache-2.0"),
    ("ISC License\n\nPermission to use\n", "ISC"),
])
def test_permissive_licenses_permit_vendoring(tmp_path, text, spdx):
    (tmp_path / "LICENSE").write_text(text, encoding="utf-8")
    finding = detect_license(tmp_path)
    assert finding.spdx == spdx and finding.vendor_allowed


@pytest.mark.parametrize("text,spdx", [(GPL, "GPL-3.0"),
                                       ("GNU AFFERO GENERAL PUBLIC LICENSE\n", "AGPL-3.0")])
def test_copyleft_is_identified_not_merely_unknown(tmp_path, text, spdx):
    """Positively identifying copyleft is what a reviewer most needs to see."""
    (tmp_path / "LICENSE").write_text(text, encoding="utf-8")
    finding = detect_license(tmp_path)
    assert finding.spdx == spdx and not finding.vendor_allowed and "copyleft" in finding.reason


def test_a_missing_license_blocks_vendor_but_notes_clone_remains(tmp_path):
    finding = detect_license(tmp_path)
    assert finding.spdx is None and not finding.vendor_allowed
    assert any("CLONE" in note for note in finding.notes)


def test_an_unrecognised_license_is_distinguished_from_a_missing_one(tmp_path):
    (tmp_path / "LICENSE").write_text("Bespoke Terms v1: ask us nicely.\n", encoding="utf-8")
    finding = detect_license(tmp_path)
    assert finding.spdx is None and finding.source_file == "LICENSE"
    assert not finding.vendor_allowed and "not recognised" in finding.reason


# ---- no LLM override -----------------------------------------------------------------------------
def test_the_decision_module_imports_no_model_client():
    """An LLM may PROPOSE evidence, but there must be no path by which it selects or overrides the
    mode. Checked structurally -- the module's own AST -- rather than by grepping prose, since the
    docstring necessarily discusses the rule it enforces."""
    import ast
    import inspect

    import kata_forge.decision as decision_module

    tree = ast.parse(inspect.getsource(decision_module))
    imported: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module)
    forbidden = {"openai", "anthropic", "kata_forge.llm", "subprocess", "httpx", "requests"}
    assert not (imported & forbidden), f"decision policy must not import {imported & forbidden}"


def test_decide_accepts_only_plain_evidence_no_callable_seam():
    """A runner/model parameter would be the seam through which a proposal could become a decision.
    ``decide`` takes one plain dataclass and nothing else."""
    import inspect
    from dataclasses import fields

    parameters = inspect.signature(decide).parameters
    assert list(parameters) == ["inputs"]

    for field in fields(DecisionInputs):
        value = getattr(_inputs(), field.name, None)
        assert not callable(value), f"DecisionInputs.{field.name} must be data, not a callable"


def test_decide_is_a_pure_function_of_its_inputs():
    inputs = _inputs(vendor_closure_files=99, vendor_entangled=["docker"], parity=_passing_parity())
    assert decide(inputs).mode == decide(inputs).mode == CLONE  # deterministic, no hidden state
