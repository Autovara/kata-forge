"""Survey many subnets at once into a ranked onboarding backlog.

M3-M4 analyze one repo; this fans that over a list of local clones and ranks them, so "which
subnet do we onboard next" becomes data instead of a hunch. A good candidate is **cheap** (FREE >
LOW > METERED), **GPU-free**, and **complete** (all three code->contract anchors found -- less to
fill by hand). Everything is offline over already-cloned repos; a repo that fails to analyze
becomes a last-ranked error row rather than aborting the survey.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from kata_forge.anchors import extract_anchors
from kata_forge.cost import estimate_cost
from kata_forge.deps import classify_repo

_COST_POINTS = {"FREE": 3, "LOW": 1, "METERED": 0}


@dataclass(frozen=True)
class SurveyRow:
    """One repo's onboarding scorecard."""

    label: str
    subnet: int | None
    cost_class: str
    needs_gpu: bool
    has_scorer: bool
    has_benchmark: bool
    has_miner: bool
    paid_providers: list[str]
    effort: str  # LOW | MEDIUM | HIGH
    score: float  # higher = better onboarding candidate
    error: str | None = None

    @property
    def anchors_found(self) -> int:
        return sum((self.has_scorer, self.has_benchmark, self.has_miner))


def _effort(cost_class: str, needs_gpu: bool, anchors_found: int) -> str:
    if anchors_found == 3 and cost_class == "FREE" and not needs_gpu:
        return "LOW"
    if anchors_found >= 2 and cost_class in {"FREE", "LOW"} and not needs_gpu:
        return "MEDIUM"
    return "HIGH"


def survey_repo(path: str | Path, *, subnet: int | None = None) -> SurveyRow:
    """Analyze one local repo into a ranked :class:`SurveyRow` (never raises)."""
    repo = Path(path).expanduser()
    label = repo.name or str(repo)
    try:
        deps = classify_repo(repo)
        anchors = extract_anchors(repo)
        cost = estimate_cost(repo, deps=deps)
    except Exception as error:  # noqa: BLE001 - a bad repo ranks last, never aborts the batch
        return SurveyRow(label, subnet, "?", False, False, False, False, [], "HIGH", float("-inf"),
                         error=str(error))
    found = sum(getattr(anchors, k) is not None for k in ("scorer", "benchmark", "miner"))
    score = _COST_POINTS.get(cost.cost_class, 0) + (0 if cost.needs_gpu else 2) + found
    return SurveyRow(
        label=label,
        subnet=subnet,
        cost_class=cost.cost_class,
        needs_gpu=cost.needs_gpu,
        has_scorer=anchors.scorer is not None,
        has_benchmark=anchors.benchmark is not None,
        has_miner=anchors.miner is not None,
        paid_providers=cost.paid_providers,
        effort=_effort(cost.cost_class, cost.needs_gpu, found),
        score=float(score),
    )


def survey(items: list) -> list[SurveyRow]:
    """Survey a list of repos (paths, or ``{"path":.., "subnet":..}`` dicts); return ranked rows."""
    rows: list[SurveyRow] = []
    for item in items:
        if isinstance(item, dict):
            rows.append(survey_repo(item["path"], subnet=item.get("subnet")))
        else:
            rows.append(survey_repo(item))
    rows.sort(key=lambda r: (-r.score, r.label))
    return rows


def render_survey_table(rows: list[SurveyRow]) -> str:
    """Render a ranked markdown onboarding table."""
    out = [
        "# kata-forge survey — onboarding backlog",
        "",
        "| # | repo | subnet | cost | gpu | anchors (s/b/m) | providers | effort |",
        "|---|---|---|---|---|---|---|---|",
    ]
    for i, r in enumerate(rows, 1):
        if r.error:
            out.append(f"| {i} | {r.label} | {r.subnet or '—'} | ERROR | — | — | — | — |")
            continue
        anchors = "".join("✓" if x else "·" for x in (r.has_scorer, r.has_benchmark, r.has_miner))
        providers = ", ".join(r.paid_providers) or "—"
        out.append(
            f"| {i} | {r.label} | {r.subnet or '—'} | {r.cost_class} | "
            f"{'yes' if r.needs_gpu else 'no'} | {anchors} | {providers} | {r.effort} |"
        )
    return "\n".join(out) + "\n"
