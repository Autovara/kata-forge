"""The S5 onboarding decision pipeline (plan 4.2 steps 0-5).

Chains the S5 pieces in the order the plan fixes, and stops at the DECISION. It deliberately does not
scaffold, draft, or emit a bundle: those are S6/S7, and keeping the boundary here means an
unsatisfiable input is refused before it ever reaches the AI compartment.

    PREFLIGHT   canonical input, mutually exclusive --repo/--subnet
    RESOLVE     --repo URL, or number -> local versioned catalog (never a guess)
    FETCH       isolated clone -> full commit SHA -> immutable snapshot
    RESEARCH    deps + embedded-credential scan + cost + license
    FREE GATE   metered/needs-keys/GPU -> REFUSE
    DECIDE      VENDOR | CLONE | REFUSE, by fixed precedence, written as a record

Measured VENDOR/CLONE proofs (a scorer closure size, an executed parity fixture) are INPUTS here
rather than something this module computes: producing them means running upstream code, which belongs
in the isolated Verify compartment (plan 7, S6). Passing them in keeps this module free of any code
execution, and keeps the decision a pure function of evidence.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from kata_forge.cost import estimate_cost
from kata_forge.decision import DecisionInputs, IntegrationDecision, decide, write_decision_record
from kata_forge.deps import classify_repo
from kata_forge.license_gate import detect_license
from kata_forge.pinned_fetch import PinnedSource, fetch_pinned
from kata_forge.redaction import scan_embedded_secrets
from kata_forge.trusted_input import CanonicalRepo, resolve_trusted_input

#: The plan names this file explicitly; every consumer reads it by this name.
INTEGRATION_DECISION_FILENAME = "integration-decision.json"


@dataclass(frozen=True)
class OnboardResult:
    canonical: CanonicalRepo
    pinned: PinnedSource
    decision: IntegrationDecision
    record_path: Path


def run_decision_pipeline(
    *,
    repo: str | None = None,
    subnet: int | None = None,
    catalog_path: str | Path | None = None,
    work_dir: str | Path,
    out_dir: str | Path,
    commit: str | None = None,
    allow_gpu: bool = False,
    git_runner=None,
    vendor_closure_files: int | None = None,
    vendor_entangled: list[str] | None = None,
    parity: dict | None = None,
) -> OnboardResult:
    """Resolve, fetch, research and decide. Writes ``integration-decision.json`` for EVERY outcome."""
    canonical = resolve_trusted_input(repo=repo, subnet=subnet, catalog_path=catalog_path)
    pinned = fetch_pinned(canonical, Path(work_dir) / f"{canonical.owner}__{canonical.repo}",
                          commit=commit, git_runner=git_runner)

    # RESEARCH. The credential scan runs FIRST among the analyses because its finding is the one that
    # must stop the pipeline before any source text could reach a model provider.
    embedded = [finding.as_evidence() for finding in scan_embedded_secrets(pinned.path)]
    deps = classify_repo(pinned.path)
    cost = estimate_cost(pinned.path, deps=deps)
    license_finding = detect_license(pinned.path)

    decision = decide(DecisionInputs(
        source_url=pinned.url,
        source_commit=pinned.commit,
        dep_verdict=deps.verdict,
        cost_class=cost.cost_class,
        needs_gpu=cost.needs_gpu,
        embedded_secrets=embedded,
        license=license_finding.as_evidence(),
        vendor_closure_files=vendor_closure_files,
        vendor_entangled=list(vendor_entangled or []),
        parity=dict(parity or {}),
        allow_gpu=allow_gpu,
    ))
    record_path = write_decision_record(Path(out_dir) / INTEGRATION_DECISION_FILENAME, decision)
    return OnboardResult(canonical=canonical, pinned=pinned, decision=decision,
                         record_path=record_path)
