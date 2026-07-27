"""The gated metered-integration policy (SN22-0).

The locked automation scope is **free validators only**: a subnet needing paid keys is detected and
refused. That default does not change here. What this adds is a narrow, explicit, reviewed way to
say "this specific metered subnet is approved, under these named credentials and these limits" —
so that onboarding a paid validator is a deliberate act with a paper trail, not a softened gate.

Four properties hold, and the tests pin each one:

* **Free stays the default.** With no policy supplied, ``METERED``/``NEEDS-KEYS`` refuses exactly as
  before. There is no environment variable, no flag, and no default file that turns metered on.
* **Names, never values.** A policy declares which credentials a lane needs by NAME. Anything that
  looks like a credential value is refused outright — a policy document is reviewed, committed, and
  copied around, and must stay safe to do all three with.
* **Provider-bound.** The policy must cover every paid provider the survey actually found. A repo
  that reaches a provider the reviewer did not authorise is refused, so the approval cannot silently
  widen when upstream adds a dependency.
* **Bounded.** A policy without enforceable per-day limits is not an approval; it is a blank cheque.

The installer independently re-checks all of this against a root-owned approval record, so a forged
policy inside a bundle cannot authorise itself.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path

POLICY_SCHEMA_VERSION = 1

#: Credential NAMES look like this. A value would not.
_NAME_RE = re.compile(r"^[A-Z][A-Z0-9_]{2,63}$")

#: Shapes that indicate someone pasted a secret VALUE where a name belongs. Deliberately broad: a
#: false positive costs a reviewer one edit, a false negative commits a live credential.
_VALUE_SHAPES = (
    re.compile(r"\bghp_[A-Za-z0-9]{20,}"),
    re.compile(r"\bsk-[A-Za-z0-9]{16,}"),
    re.compile(r"\bapify_api_[A-Za-z0-9]{16,}", re.IGNORECASE),
    re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    re.compile(r"^[A-Za-z0-9+/]{40,}={0,2}$"),   # a long opaque blob
)

#: Budget dimensions a metered policy may bound. Mirrors kata_bot.budget.DIMENSIONS plus the
#: provider-unit dimensions a search subnet needs, because call count alone cannot price them.
KNOWN_DIMENSIONS = frozenset({
    "inference_calls", "tokens", "spend_usd", "tee_runs", "data_api_calls", "scrape_units",
})


class MeteredPolicyError(Exception):
    """The policy is malformed, unbounded, or carries a credential value. Fail closed."""


@dataclass(frozen=True)
class MeteredPolicy:
    """One reviewer's explicit approval to onboard one metered subnet."""

    subnet_id: int
    approved_by: str
    approved_at: str
    #: Paid providers this approval covers. The survey's findings must be a SUBSET of these.
    providers: tuple[str, ...]
    #: Credential NAMES the lane's gateway will hold. Never values.
    credential_names: tuple[str, ...]
    #: Per-day hard limits, keyed by budget dimension. At least one is required.
    daily_limits: dict[str, float] = field(default_factory=dict)
    notes: str = ""

    def covers(self, observed_providers) -> tuple[bool, str]:
        """Whether this approval covers everything the survey actually found."""
        missing = sorted(set(observed_providers) - set(self.providers))
        if missing:
            return False, (f"the source reaches paid provider(s) {', '.join(missing)} which this "
                           f"approval does not cover")
        return True, ""

    def as_evidence(self) -> dict:
        """The record that lands in the decision and the bundle. Names and bounds only."""
        return {
            "schema_version": POLICY_SCHEMA_VERSION,
            "subnet_id": self.subnet_id,
            "approved_by": self.approved_by,
            "approved_at": self.approved_at,
            "providers": sorted(self.providers),
            "credential_names": sorted(self.credential_names),
            "daily_limits": dict(sorted(self.daily_limits.items())),
            "notes": self.notes,
        }


def _reject_credential_values(document: object, where: str = "policy") -> None:
    """Refuse a policy carrying anything value-shaped, anywhere in the document."""
    if isinstance(document, str):
        for shape in _VALUE_SHAPES:
            if shape.search(document):
                raise MeteredPolicyError(
                    f"{where} contains something shaped like a credential VALUE. A metered policy "
                    f"declares credential NAMES only.")
    elif isinstance(document, dict):
        for key, value in document.items():
            _reject_credential_values(key, where)
            _reject_credential_values(value, f"{where}.{key}")
    elif isinstance(document, list):
        for index, item in enumerate(document):
            _reject_credential_values(item, f"{where}[{index}]")


def parse_metered_policy(document: object) -> MeteredPolicy:
    """Validate a metered-policy document, or refuse."""
    if not isinstance(document, dict):
        raise MeteredPolicyError("metered policy must be a JSON object")
    _reject_credential_values(document)

    if document.get("schema_version") != POLICY_SCHEMA_VERSION:
        raise MeteredPolicyError(
            f"metered policy schema_version {document.get('schema_version')!r} is not "
            f"{POLICY_SCHEMA_VERSION}")

    subnet_id = document.get("subnet_id")
    if isinstance(subnet_id, bool) or not isinstance(subnet_id, int) or subnet_id <= 0:
        raise MeteredPolicyError(f"subnet_id must be a positive int, got {subnet_id!r}")

    approved_by = str(document.get("approved_by") or "").strip()
    approved_at = str(document.get("approved_at") or "").strip()
    if not approved_by or not approved_at:
        raise MeteredPolicyError("a metered policy must record approved_by and approved_at")

    providers = document.get("providers")
    if not isinstance(providers, list) or not providers:
        raise MeteredPolicyError("a metered policy must name at least one paid provider")

    names = document.get("credential_names")
    if not isinstance(names, list) or not names:
        raise MeteredPolicyError("a metered policy must declare the credential NAMES it authorises")
    for name in names:
        if not isinstance(name, str) or not _NAME_RE.match(name):
            raise MeteredPolicyError(
                f"credential name {name!r} does not look like an environment variable NAME "
                f"(A-Z, digits, underscore)")

    limits_raw = document.get("daily_limits")
    if not isinstance(limits_raw, dict) or not limits_raw:
        raise MeteredPolicyError(
            "a metered policy must set at least one per-day hard limit; an unbounded approval is a "
            "blank cheque, not an approval")
    limits: dict[str, float] = {}
    for dimension, value in limits_raw.items():
        if dimension not in KNOWN_DIMENSIONS:
            raise MeteredPolicyError(
                f"unknown budget dimension {dimension!r}; known: {sorted(KNOWN_DIMENSIONS)}")
        if isinstance(value, bool) or not isinstance(value, (int, float)) or value <= 0:
            raise MeteredPolicyError(f"daily_limits[{dimension!r}] must be a positive number")
        limits[dimension] = float(value)

    return MeteredPolicy(
        subnet_id=subnet_id, approved_by=approved_by, approved_at=approved_at,
        providers=tuple(str(p) for p in providers),
        credential_names=tuple(str(n) for n in names),
        daily_limits=limits, notes=str(document.get("notes") or ""),
    )


def load_metered_policy(path: str | Path) -> MeteredPolicy:
    target = Path(path).expanduser()
    try:
        document = json.loads(target.read_text(encoding="utf-8"))
    except OSError as exc:
        raise MeteredPolicyError(f"cannot read metered policy {target}: {exc}") from exc
    except ValueError as exc:
        raise MeteredPolicyError(f"invalid JSON in metered policy {target}: {exc}") from exc
    return parse_metered_policy(document)
