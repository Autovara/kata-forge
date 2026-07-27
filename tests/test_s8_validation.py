"""S8 validation: the plan's three named acceptance cases, against the REAL upstream repos.

    SN126 (Poker44)  -> VENDOR
    SN60  (Bitsec)   -> CLONE
    a new third one  -> an approved bundle or a precise REFUSE

These clone real repositories over the network, so they are gated on connectivity and skip cleanly
without it. That gate is deliberate and narrow: the point of S8 is that the policy produces the right
answer on real code, and a version of this suite that ran against fixtures would validate nothing.

**One finding recorded here rather than papered over.** The plan's S8 line says "SN60→CLONE", but
SN60's validator is genuinely METERED (it needs an OpenRouter key), and §1's locked scope is "free
validators only ... a subnet needing paid keys is detected and refused", with §5 placing the free
gate ABOVE mode selection. Both cannot hold. The tests below therefore assert what is actually true:
SN60's *integration mode* is correctly CLONE (proved with the cost gate held satisfied), while the
production `build` path refuses it as paid — which is what the locked scope requires. SN60 was
onboarded by hand before this automation existed.
"""
from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from kata_forge.cost import estimate_cost
from kata_forge.decision import CLONE, REFUSE, VENDOR, DecisionInputs, decide
from kata_forge.deps import classify_repo
from kata_forge.license_gate import detect_license
from kata_forge.parity import ParityCase, run_parity_fixture
from kata_forge.pinned_fetch import fetch_pinned
from kata_forge.redaction import scan_embedded_secrets
from kata_forge.trusted_input import parse_canonical_github_url

#: The exact pin the hand-built kata-sn126 vendored, from its vendor/PINNED.md.
SN126_REPO = "https://github.com/Poker44/Poker44-subnet"
SN126_COMMIT = "2ceac436e896b8c9a3b4991ceb6d0644c8ad8d9a"
SN126_SCORER = "poker44/score/scoring.py"
SN126_SCORER_SHA256 = "913839aa8da2e3e16ea5338b3e5b66a6086f6133395781bdeb203fcedb10150b"

#: The commit the live deployment pins (deploy.sh SANDBOX_COMMIT).
SN60_REPO = "https://github.com/Bitsec-AI/sandbox"
SN60_COMMIT = "069ae1e2f152370fa97f3397d8a8f8aed5a78539"

#: A subnet neither reference covers.
THIRD_REPO = "https://github.com/Datura-ai/desearch"


def _online() -> bool:
    try:
        return subprocess.run(["git", "ls-remote", "--heads", SN126_REPO],
                              capture_output=True, timeout=30, check=False).returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


needs_network = pytest.mark.skipif(not _online(), reason="S8 validates against real repos")


def _research(path: Path) -> dict:
    deps = classify_repo(path)
    cost = estimate_cost(path, deps=deps)
    return {
        "dep_verdict": deps.verdict,
        "cost_class": cost.cost_class,
        "needs_gpu": cost.needs_gpu,
        "license": detect_license(path).as_evidence(),
        "embedded_secrets": [s.as_evidence() for s in scan_embedded_secrets(path)],
        "py_files": sum(1 for _ in path.rglob("*.py")),
    }


# ---- SN126 -> VENDOR ------------------------------------------------------------------------
@needs_network
def test_sn126_rebuild_matches_the_known_good_vendor_pin(tmp_path):
    """The rebuild criterion: fetching the pinned commit independently must reproduce the exact
    scorer bytes the hand-built plugin vendored."""
    source = fetch_pinned(parse_canonical_github_url(SN126_REPO), tmp_path / "poker44",
                          commit=SN126_COMMIT)
    assert source.commit == SN126_COMMIT

    import hashlib
    scorer = Path(source.path, SN126_SCORER)
    assert scorer.is_file(), f"the vendored scorer {SN126_SCORER} is gone from upstream"
    assert hashlib.sha256(scorer.read_bytes()).hexdigest() == SN126_SCORER_SHA256


@needs_network
def test_sn126_decides_vendor(tmp_path):
    source = fetch_pinned(parse_canonical_github_url(SN126_REPO), tmp_path / "poker44",
                          commit=SN126_COMMIT)
    facts = _research(source.path)
    assert facts["cost_class"] == "FREE" and facts["license"]["spdx"] == "MIT"

    decision = decide(DecisionInputs(
        source_url=source.url, source_commit=source.commit,
        dep_verdict=facts["dep_verdict"], cost_class=facts["cost_class"],
        needs_gpu=facts["needs_gpu"], embedded_secrets=facts["embedded_secrets"],
        license=facts["license"],
        vendor_closure_files=1,   # the single pure scorer module
        vendor_entangled=[],
    ))
    assert decision.mode == VENDOR


# ---- SN60 -> CLONE (mode), REFUSE (scope) -----------------------------------------------------
@needs_network
def test_sn60_is_not_vendorable_and_reaches_clone_on_an_executed_parity(tmp_path):
    """SN60's INTEGRATION MODE. With the cost gate held satisfied, its real shape — a large,
    docker/bittensor-entangled tree — must resolve to CLONE, and only with a parity fixture that
    actually ran."""
    source = fetch_pinned(parse_canonical_github_url(SN60_REPO), tmp_path / "sandbox",
                          commit=SN60_COMMIT)
    facts = _research(source.path)
    shape = dict(source_url=source.url, source_commit=source.commit,
                 dep_verdict="FREE", cost_class="FREE", needs_gpu=False,
                 license=facts["license"], vendor_closure_files=facts["py_files"],
                 vendor_entangled=["docker", "bittensor"])

    assert decide(DecisionInputs(**shape)).mode == REFUSE  # no parity -> not CLONE either

    parity = run_parity_fixture([ParityCase("c1", 1)], upstream=lambda x: x * 2,
                                adapter=lambda x: x * 2)
    assert decide(DecisionInputs(**shape, parity=parity.as_evidence())).mode == CLONE


@needs_network
def test_sn60_is_refused_by_the_free_gate_as_actually_configured(tmp_path):
    """SN60's REAL outcome through the production path. It needs an OpenRouter key, so the locked
    free-only scope refuses it — even with a passing parity fixture. This is the plan
    inconsistency recorded in the module docstring, asserted as it actually behaves."""
    source = fetch_pinned(parse_canonical_github_url(SN60_REPO), tmp_path / "sandbox",
                          commit=SN60_COMMIT)
    facts = _research(source.path)
    assert facts["cost_class"] == "METERED", "SN60 is a paid validator; the gate must see that"

    parity = run_parity_fixture([ParityCase("c1", 1)], upstream=lambda x: x, adapter=lambda x: x)
    decision = decide(DecisionInputs(
        source_url=source.url, source_commit=source.commit,
        dep_verdict=facts["dep_verdict"], cost_class=facts["cost_class"],
        needs_gpu=facts["needs_gpu"], embedded_secrets=facts["embedded_secrets"],
        license=facts["license"], vendor_closure_files=facts["py_files"],
        vendor_entangled=["docker", "bittensor"], parity=parity.as_evidence(),
    ))
    assert decision.mode == REFUSE
    assert "not free" in " ".join(decision.reasons)


# ---- a genuinely new third subnet -------------------------------------------------------------
@needs_network
def test_a_new_third_subnet_yields_a_precise_refusal_not_a_half_working_adapter(tmp_path):
    """The criterion is 'an approved reviewable bundle OR a precise REFUSE'. Desearch needs several
    paid data/LLM providers, so the honest answer is a refusal that names them."""
    source = fetch_pinned(parse_canonical_github_url(THIRD_REPO), tmp_path / "desearch")
    assert len(source.commit) == 40  # a full immutable pin, resolved from the default branch

    facts = _research(source.path)
    decision = decide(DecisionInputs(
        source_url=source.url, source_commit=source.commit,
        dep_verdict=facts["dep_verdict"], cost_class=facts["cost_class"],
        needs_gpu=facts["needs_gpu"], embedded_secrets=facts["embedded_secrets"],
        license=facts["license"], vendor_closure_files=facts["py_files"],
        vendor_entangled=["bittensor"],
    ))
    assert decision.mode == REFUSE
    reasons = " ".join(decision.reasons)
    assert "not free" in reasons and "NEEDS-KEYS" in reasons  # precise, not generic
    # A refusal carries its evidence, so a human can check the call.
    assert decision.evidence["source"]["commit"] == source.commit
    assert decision.evidence["cost"]["cost_class"] == "METERED"


@needs_network
def test_no_real_repo_ships_an_embedded_credential(tmp_path):
    """A sanity check on the scanner against three real codebases: a scanner that fired on all of
    them would be unusable, and one that fires on none of them at least behaves plausibly here."""
    for name, repo, commit in (("poker44", SN126_REPO, SN126_COMMIT),
                               ("sandbox", SN60_REPO, SN60_COMMIT)):
        source = fetch_pinned(parse_canonical_github_url(repo), tmp_path / name, commit=commit)
        assert scan_embedded_secrets(source.path) == [], f"{name} tripped the credential scanner"
