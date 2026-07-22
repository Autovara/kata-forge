"""Fold deps (M3.2) + secrets (M4.1) into an honest onboarding cost verdict.

M3.2's FREE / NEEDS-KEYS / NEEDS-GPU is coarse. This adds the money signal an operator actually
needs: a **cost class** (FREE / LOW / METERED), the paid providers + keys behind it, and whether a
GPU is required. Cost class is driven by *known* paid providers (per-challenge inference/scrape =
METERED; flat/gated access = LOW) plus GPU/gated-data. Crucially, an *unattributed* required secret
(a repo reading a validator-internal key the scoring path may not even use -- e.g. Poker44's
provider secret, which the pinned public benchmark replaces) is a **note, not a cost bump**: it is
surfaced for review but never silently pushes a free subnet off FREE.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from kata_forge.deps import DepReport, classify_repo
from kata_forge.secrets import FREE_TIER_PROVIDERS, SecretReport, extract_secrets

# per-call cost (inference / scrape) -> METERED; flat / gated access -> LOW.
_METERED_PROVIDERS = frozenset({
    "openai", "anthropic", "cohere", "mistral", "groq", "together", "openrouter", "replicate",
    "apify", "scrapingdog", "serpapi", "tavily", "firecrawl",
})
_LOW_PROVIDERS = frozenset({"aws", "huggingface"})
# paid-api dependency (lib) -> provider, so an imported SDK counts even without an env key found.
_PROVIDER_BY_LIB = {
    "openai": "openai", "anthropic": "anthropic", "cohere": "cohere", "mistralai": "mistral",
    "groq": "groq", "together": "together", "replicate": "replicate", "apify-client": "apify",
    "scrapingdog": "scrapingdog", "serpapi": "serpapi", "google-search-results": "serpapi",
    "boto3": "aws", "botocore": "aws", "tavily-python": "tavily", "firecrawl-py": "firecrawl",
}


@dataclass(frozen=True)
class CostReport:
    """An onboarding cost verdict richer than FREE/NEEDS-KEYS."""

    cost_class: str  # FREE | LOW | METERED
    needs_gpu: bool
    paid_providers: list[str]  # known paid providers driving the class
    required_secrets: list[str]
    summary: str  # one-line human verdict
    notes: list[str] = field(default_factory=list)


def _providers_from_deps(deps: DepReport) -> set[str]:
    return {_PROVIDER_BY_LIB[lib] for lib in deps.paid_api if lib in _PROVIDER_BY_LIB}


def estimate_cost(
    repo: str | Path,
    *,
    deps: DepReport | None = None,
    secrets: SecretReport | None = None,
) -> CostReport:
    """Estimate what it costs to validate this subnet: cost class + providers + GPU."""
    repo = Path(repo).expanduser()
    deps = deps or classify_repo(repo)
    secrets = secrets or extract_secrets(repo)

    providers = set(secrets.paid_providers) | _providers_from_deps(deps)
    metered = sorted(p for p in providers if p in _METERED_PROVIDERS)
    low = sorted(p for p in providers if p in _LOW_PROVIDERS)
    needs_gpu = bool(deps.gpu)

    notes: list[str] = []
    if deps.gated_data:
        notes.append(f"gated data: {', '.join(deps.gated_data)} (may need an access token)")
    if needs_gpu:
        notes.append(f"GPU required: {', '.join(deps.gpu)}")
    # required secrets not tied to any known provider and not free-tier: flag, do NOT bump cost.
    attributed = set(secrets.providers)
    unattributed = [
        s for s in secrets.required_secrets
        if not any(p in s.lower() for p in attributed)
        and not any(free in s.lower() for free in FREE_TIER_PROVIDERS)
    ]
    if unattributed:
        notes.append(
            "unattributed required secrets (confirm the scoring path needs them): "
            + ", ".join(unattributed)
        )

    if metered:
        cost_class = "METERED"
    elif low or deps.gated_data:
        cost_class = "LOW"
    else:
        cost_class = "FREE"

    paid = sorted(providers)
    bits = [cost_class]
    if paid:
        bits.append(f"providers: {', '.join(paid)}")
    if needs_gpu:
        bits.append("needs GPU")
    if cost_class == "FREE" and not needs_gpu:
        bits = ["FREE — no keys, no GPU"]
    summary = " · ".join(bits)
    return CostReport(
        cost_class=cost_class,
        needs_gpu=needs_gpu,
        paid_providers=paid,
        required_secrets=secrets.required_secrets,
        summary=summary,
        notes=notes,
    )
