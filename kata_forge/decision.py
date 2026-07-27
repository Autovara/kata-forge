"""The three-outcome integration decision and its record (plan 5, S5).

One rule governs this module: **the mode is selected by deterministic policy over measurable
evidence, never by a model.** An LLM may propose evidence — a shape assessment, a suggested closure —
but the evidence it proposes is subject to the same gates as any other, and it can neither select nor
override the outcome. That is why ``decide`` takes plain data and contains no model call: there is no
seam through which a proposal could become a decision.

The precedence is fixed and ordered, exactly as the plan states it:

  1. input / pin / secret / license failure  -> REFUSE
  2. free-vs-paid gate, GPU gate             -> REFUSE
  3. a verified VENDOR proof                 -> VENDOR
  4. a verified CLONE parity fixture         -> CLONE
  5. otherwise                               -> REFUSE

Order matters and is not an implementation detail. A repository with an embedded credential must
refuse *before* anyone asks whether its scorer is vendorable; a metered subnet must refuse before a
parity fixture is allowed to justify cloning it. Checking cheap disqualifiers first is also what
keeps an unsatisfiable input from reaching the AI compartment at all.

**One deliberate reading of the plan, flagged because the text is not self-consistent.** §5's
precedence summary lists "license failure" among the step-1 REFUSE gates, but §7.1 states the
specific rule: "License review before vendoring; incompatible/missing => CLONE or REFUSE". This
module implements §7.1 — a licence that does not permit vendoring blocks VENDOR and leaves CLONE
reachable — because cloning and running upstream at a pinned commit is not redistribution, so an
unclear licence is a reason not to COPY rather than a reason to abandon the subnet. Reading it the
other way would refuse every GPL-licensed validator outright, which §7.1 plainly does not intend.

``REFUSE`` is always ``REFUSE / NEEDS-HUMAN``: a precise reason, never a half-working adapter.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

from kata_forge.redaction import redact

#: Bumped whenever the precedence or a gate changes, so a record made under different rules is
#: recognisable rather than silently comparable.
POLICY_VERSION = "s5.v1"

VENDOR = "VENDOR"
CLONE = "CLONE"
REFUSE = "REFUSE"

#: A vendored scorer must be a small pure closure. Above this it is not a "pure-shaped scorer" any
#: more, and cloning at a pin is the honest integration.
MAX_VENDOR_FILES = 3


@dataclass(frozen=True)
class DecisionInputs:
    """Everything the policy is allowed to look at. Plain data, deliberately: no runner, no model."""

    source_url: str
    source_commit: str
    #: kata_forge.deps.DepReport verdict: FREE | NEEDS-KEYS | NEEDS-GPU
    dep_verdict: str
    #: kata_forge.cost.CostReport cost_class: FREE | LOW | METERED
    cost_class: str
    needs_gpu: bool
    #: kata_forge.redaction.EmbeddedSecret evidence dicts. Non-empty => REFUSE.
    embedded_secrets: list[dict] = field(default_factory=list)
    #: kata_forge.license_gate.LicenseFinding evidence dict.
    license: dict = field(default_factory=dict)
    #: Measured VENDOR proof: the scorer's closure size and entanglement flags.
    vendor_closure_files: int | None = None
    vendor_entangled: list[str] = field(default_factory=list)
    #: kata_forge.parity.ParityResult evidence dict.
    parity: dict = field(default_factory=dict)
    anchors: list[str] = field(default_factory=list)
    allow_gpu: bool = False


@dataclass(frozen=True)
class IntegrationDecision:
    """The selected mode plus the exact evidence that selected it."""

    mode: str
    reasons: list[str]
    evidence: dict
    policy_version: str = POLICY_VERSION

    @property
    def refused(self) -> bool:
        return self.mode == REFUSE


def _input_gates(inputs: DecisionInputs) -> list[str]:
    """Step 1: input / pin / secret / license failures. Returns refusal reasons (empty == pass)."""
    reasons: list[str] = []
    if not inputs.source_url:
        reasons.append("no canonical source URL was resolved")
    if not isinstance(inputs.source_commit, str) or len(inputs.source_commit) != 40:
        reasons.append(
            f"source commit {inputs.source_commit!r} is not a full 40-character sha; the build is "
            f"not reproducibly pinned")
    if inputs.embedded_secrets:
        kinds = sorted({str(item.get("kind")) for item in inputs.embedded_secrets})
        # Refuse BEFORE any AI input: drafting would transmit the credential to a model provider.
        reasons.append(
            f"{len(inputs.embedded_secrets)} embedded credential(s) found in the source "
            f"({', '.join(kinds)}); refusing before any AI input")
    return reasons


def _cost_gates(inputs: DecisionInputs) -> list[str]:
    """Step 2: the free/GPU gate. Paid validators are out of scope for automation entirely."""
    reasons: list[str] = []
    if inputs.cost_class == "METERED" or inputs.dep_verdict == "NEEDS-KEYS":
        reasons.append(
            f"validator is not free (cost_class={inputs.cost_class}, deps={inputs.dep_verdict}); "
            f"paid validators are out of scope for automated onboarding")
    if inputs.needs_gpu and not inputs.allow_gpu:
        reasons.append("validator requires a GPU; pass --allow-gpu to override explicitly")
    return reasons


def _vendor_proof(inputs: DecisionInputs) -> tuple[bool, list[str]]:
    """Step 3: is there a MEASURED proof this scorer can be vendored? Returns (ok, notes)."""
    notes: list[str] = []
    closure = inputs.vendor_closure_files
    if closure is None:
        notes.append("no vendor closure was measured")
        return False, notes
    if closure > MAX_VENDOR_FILES:
        notes.append(f"scorer closure is {closure} files (> {MAX_VENDOR_FILES}); not a pure-shaped scorer")
        return False, notes
    if inputs.vendor_entangled:
        notes.append(f"scorer is entangled with {', '.join(sorted(inputs.vendor_entangled))}")
        return False, notes
    if not inputs.license.get("vendor_allowed"):
        # A license failure blocks VENDOR specifically; CLONE is still reachable below.
        notes.append(f"license does not permit vendoring: {inputs.license.get('reason', 'unreviewed')}")
        return False, notes
    notes.append(f"closure {closure} file(s), no entanglement, license "
                 f"{inputs.license.get('spdx')} permits vendoring")
    return True, notes


def _clone_proof(inputs: DecisionInputs) -> tuple[bool, list[str]]:
    """Step 4: did a parity fixture ACTUALLY EXECUTE and match?"""
    parity = inputs.parity or {}
    executed = bool(parity.get("executed"))
    matched = bool(parity.get("matched"))
    cases = int(parity.get("cases_run") or 0)
    mismatches = parity.get("mismatches") or []
    if not executed:
        return False, [f"parity fixture did not execute ({parity.get('error') or 'not run'}); "
                       f"a fixture that never ran is not a pass"]
    if cases <= 0:
        return False, ["parity fixture executed zero cases; comparing nothing always matches"]
    if not matched or mismatches:
        return False, [f"parity fixture executed {cases} case(s) and disagreed: "
                       f"{json.dumps(mismatches)[:300]}"]
    return True, [f"parity fixture executed {cases} case(s) and matched"]


def decide(inputs: DecisionInputs) -> IntegrationDecision:
    """Select VENDOR / CLONE / REFUSE by fixed precedence over measurable evidence."""
    evidence = {
        "source": {"url": inputs.source_url, "commit": inputs.source_commit},
        "dependencies": {"verdict": inputs.dep_verdict},
        "cost": {"cost_class": inputs.cost_class, "needs_gpu": inputs.needs_gpu,
                 "allow_gpu": inputs.allow_gpu},
        "embedded_secrets": inputs.embedded_secrets,
        "license": inputs.license,
        "vendor": {"closure_files": inputs.vendor_closure_files,
                   "entangled": sorted(inputs.vendor_entangled)},
        "parity": inputs.parity,
        "anchors": sorted(inputs.anchors),
    }

    blocking = _input_gates(inputs)
    if blocking:
        return IntegrationDecision(mode=REFUSE, reasons=blocking, evidence=evidence)

    blocking = _cost_gates(inputs)
    if blocking:
        return IntegrationDecision(mode=REFUSE, reasons=blocking, evidence=evidence)

    vendor_ok, vendor_notes = _vendor_proof(inputs)
    evidence["vendor"]["notes"] = vendor_notes
    if vendor_ok:
        return IntegrationDecision(mode=VENDOR, reasons=vendor_notes, evidence=evidence)

    clone_ok, clone_notes = _clone_proof(inputs)
    evidence["parity"] = {**(inputs.parity or {}), "notes": clone_notes}
    if clone_ok:
        return IntegrationDecision(mode=CLONE, reasons=clone_notes, evidence=evidence)

    return IntegrationDecision(
        mode=REFUSE,
        reasons=[*vendor_notes, *clone_notes,
                 "neither a vendor proof nor an executed parity fixture qualified; "
                 "REFUSE / NEEDS-HUMAN rather than emit a half-working adapter"],
        evidence=evidence,
    )


def _redact_tree(value):
    """Redact every string anywhere in the record. A decision record is written to disk and read by
    tools that were never vetted to hold a live credential."""
    if isinstance(value, str):
        return redact(value)
    if isinstance(value, dict):
        return {key: _redact_tree(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_redact_tree(item) for item in value]
    return value


def decision_document(decision: IntegrationDecision) -> dict:
    """The canonical, fully redacted record body."""
    return _redact_tree({
        "schema_version": 1,
        "policy_version": decision.policy_version,
        "mode": decision.mode,
        "reasons": decision.reasons,
        "evidence": decision.evidence,
    })


def write_decision_record(path: str | Path, decision: IntegrationDecision) -> Path:
    """Write ``integration-decision.json`` in canonical form (sorted keys, 2-space, newline).

    Written for EVERY outcome including REFUSE: a refusal with evidence is the deliverable when a
    subnet cannot be onboarded, and it is what a human reviews to decide whether to override.
    """
    target = Path(path).expanduser()
    target.parent.mkdir(parents=True, exist_ok=True)
    body = json.dumps(decision_document(decision), sort_keys=True, indent=2, ensure_ascii=False) + "\n"
    target.write_text(body, encoding="utf-8")
    return target
