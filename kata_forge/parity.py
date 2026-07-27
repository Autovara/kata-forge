"""The executed parity fixture (plan 5, S5).

CLONE + VERIFIED-ADAPTER means: Kata drives the upstream validator through a generated adapter, and
the adapter's answer is the upstream's answer. The plan permits that mode only when "a parity fixture
actually executed and matched" — and the emphasis on *actually executed* is the whole point.

The failure this prevents is a fixture that never ran. A comparison that defaults to "equal" when
both sides are empty, a runner that swallowed an exception, a fixture that was skipped because the
upstream import failed — each produces "no mismatch" and would otherwise read as a pass. So a
``ParityResult`` distinguishes three states, and only one of them can select CLONE:

  * ``executed=False`` — the fixture did not run. NOT a pass.
  * ``executed=True, matched=False`` — it ran and disagreed. A refusal with evidence.
  * ``executed=True, matched=True`` — the only state that qualifies, and only with real cases.

An empty case list cannot qualify either: comparing nothing always "matches".
"""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

#: Given one case input, produce a comparable answer. Either side may raise; that is a failure, not
#: a match.
ParityRunner = Callable[[Any], Any]


@dataclass(frozen=True)
class ParityCase:
    """One deterministic input both sides must agree on."""

    name: str
    payload: Any


@dataclass(frozen=True)
class ParityResult:
    """Whether the fixture ran, and whether both sides agreed."""

    executed: bool
    matched: bool
    cases_run: int
    mismatches: list[dict] = field(default_factory=list)
    error: str | None = None

    @property
    def qualifies_for_clone(self) -> bool:
        """CLONE requires a fixture that RAN, over at least one real case, and agreed everywhere."""
        return self.executed and self.matched and self.cases_run > 0 and not self.mismatches

    def as_evidence(self) -> dict:
        return {"executed": self.executed, "matched": self.matched, "cases_run": self.cases_run,
                "mismatches": self.mismatches, "error": self.error}


def run_parity_fixture(
    cases: list[ParityCase],
    *,
    upstream: ParityRunner,
    adapter: ParityRunner,
    compare: Callable[[Any, Any], bool] | None = None,
) -> ParityResult:
    """Execute both sides over every case and report agreement.

    Any exception from either side is recorded as a failure rather than propagating: the caller's
    job is to make a decision, and "the upstream scorer crashed on our fixture" is decision-relevant
    evidence, not an error to abort on.
    """
    equal = compare or (lambda a, b: a == b)
    if not cases:
        # Vacuous truth is the trap this guards: zero cases would otherwise "match" perfectly.
        return ParityResult(executed=False, matched=False, cases_run=0,
                            error="no parity cases supplied; an empty fixture cannot verify anything")

    mismatches: list[dict] = []
    cases_run = 0
    for case in cases:
        try:
            expected = upstream(case.payload)
        except Exception as exc:  # noqa: BLE001 - upstream failure is evidence, not a crash
            return ParityResult(executed=True, matched=False, cases_run=cases_run,
                                error=f"upstream raised on case {case.name!r}: {exc}")
        try:
            actual = adapter(case.payload)
        except Exception as exc:  # noqa: BLE001
            return ParityResult(executed=True, matched=False, cases_run=cases_run,
                                error=f"adapter raised on case {case.name!r}: {exc}")
        cases_run += 1
        try:
            agreed = bool(equal(expected, actual))
        except Exception as exc:  # noqa: BLE001 - a comparator that raises is not a match
            return ParityResult(executed=True, matched=False, cases_run=cases_run,
                                error=f"comparison raised on case {case.name!r}: {exc}")
        if not agreed:
            mismatches.append({"case": case.name, "upstream": repr(expected)[:200],
                               "adapter": repr(actual)[:200]})
    return ParityResult(executed=True, matched=not mismatches, cases_run=cases_run,
                        mismatches=mismatches)
