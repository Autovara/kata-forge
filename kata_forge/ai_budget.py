"""Bounded, redacted, non-authoritative AI drafting (plan 6, S6).

AI drafting is the step with the least predictable cost and the largest blast radius, so it is
**off by default and stays off** unless every bound is explicitly configured. There is no
"reasonable default" path into spending: an unset limit disables drafting rather than assuming one.

Four bounds, all required and all positive:

======================================  ===========================================================
``KATA_FORGE_AI_MAX_ATTEMPTS``          retries per method (defaults to 3)
``KATA_FORGE_AI_MAX_WALL_SECONDS``      total drafting time for the build
``KATA_FORGE_AI_MAX_INPUT_BYTES``       total prompt bytes sent
``KATA_FORGE_AI_MAX_OUTPUT_TOKENS``     per-request cap the PROVIDER enforces
======================================  ===========================================================

USD is a hard cap only when the provider offers a reliable per-request spend cap
(``KATA_FORGE_AI_MAX_SPEND_USD`` plus ``KATA_FORGE_AI_PROVIDER_ENFORCES_SPEND=1``). Otherwise it is
observation-only and must not be described as a cap — the same honesty rule as the runtime budget
in §8.3.

The budget is checked **before every call**, never after. Exhaustion is ``REFUSE / NEEDS-HUMAN``,
never a partial working claim: a method whose draft did not complete is reported UNRESOLVED and falls
back to the anchored stub.

``ai-usage.json`` records what was spent and nothing about what was said. No raw prompt, no source
text, no credential — only counts, hashes, timings and outcomes.
"""
from __future__ import annotations

import hashlib
import json
import os
import time
from dataclasses import dataclass, field
from pathlib import Path

MAX_ATTEMPTS_ENV = "KATA_FORGE_AI_MAX_ATTEMPTS"
MAX_WALL_SECONDS_ENV = "KATA_FORGE_AI_MAX_WALL_SECONDS"
MAX_INPUT_BYTES_ENV = "KATA_FORGE_AI_MAX_INPUT_BYTES"
MAX_OUTPUT_TOKENS_ENV = "KATA_FORGE_AI_MAX_OUTPUT_TOKENS"
MAX_SPEND_USD_ENV = "KATA_FORGE_AI_MAX_SPEND_USD"
PROVIDER_ENFORCES_SPEND_ENV = "KATA_FORGE_AI_PROVIDER_ENFORCES_SPEND"

DEFAULT_MAX_ATTEMPTS = 3
AI_USAGE_FILENAME = "ai-usage.json"


class AiDraftingDisabled(Exception):
    """Drafting is not configured. NOT an error: the build proceeds with anchored stubs."""


class AiBudgetExhausted(Exception):
    """A bound was reached. REFUSE / NEEDS-HUMAN — never a partial working claim."""


@dataclass(frozen=True)
class AiLimits:
    """The configured bounds. Constructed only when every required one is present and positive."""

    max_attempts: int
    max_wall_seconds: float
    max_input_bytes: int
    max_output_tokens: int
    max_spend_usd: float | None = None
    spend_is_hard_cap: bool = False

    def as_evidence(self) -> dict:
        return {
            "max_attempts": self.max_attempts,
            "max_wall_seconds": self.max_wall_seconds,
            "max_input_bytes": self.max_input_bytes,
            "max_output_tokens": self.max_output_tokens,
            "max_spend_usd": self.max_spend_usd,
            # Named precisely: an unenforceable USD number is observation, not a cap.
            "spend_enforcement": "hard-cap" if self.spend_is_hard_cap else "observation-only",
        }


def _positive_number(env: dict[str, str], var: str, cast):
    raw = (env.get(var) or "").strip()
    if raw == "":
        raise AiDraftingDisabled(
            f"{var} is not set; AI drafting stays disabled until every bound is configured")
    try:
        value = cast(raw)
    except ValueError as exc:
        raise AiDraftingDisabled(f"{var} is not a number: {raw!r}") from exc
    if value <= 0:
        raise AiDraftingDisabled(f"{var} must be positive, got {value!r}")
    return value


def limits_from_env(env: dict[str, str] | None = None) -> AiLimits:
    """The configured limits, or ``AiDraftingDisabled`` if any required bound is missing."""
    env = dict(os.environ if env is None else env)
    raw_attempts = (env.get(MAX_ATTEMPTS_ENV) or "").strip()
    if raw_attempts == "":
        attempts = DEFAULT_MAX_ATTEMPTS
    else:
        attempts = _positive_number(env, MAX_ATTEMPTS_ENV, int)

    wall = _positive_number(env, MAX_WALL_SECONDS_ENV, float)
    input_bytes = _positive_number(env, MAX_INPUT_BYTES_ENV, int)
    output_tokens = _positive_number(env, MAX_OUTPUT_TOKENS_ENV, int)

    spend_raw = (env.get(MAX_SPEND_USD_ENV) or "").strip()
    spend = float(spend_raw) if spend_raw else None
    # A USD number is a HARD cap only if the provider itself enforces it per request. Without that
    # the build can observe spend but cannot bound it, and must not claim otherwise.
    enforced = (env.get(PROVIDER_ENFORCES_SPEND_ENV) or "").strip().lower() in {"1", "true", "yes", "on"}
    return AiLimits(max_attempts=attempts, max_wall_seconds=wall, max_input_bytes=input_bytes,
                    max_output_tokens=output_tokens, max_spend_usd=spend,
                    spend_is_hard_cap=bool(spend is not None and enforced))


@dataclass
class AiUsage:
    """Running totals plus the per-attempt provenance. Counts and hashes only — never content."""

    build_id: str
    provider: str
    model: str
    limits: AiLimits
    attempts: list[dict] = field(default_factory=list)
    input_bytes: int = 0
    input_tokens: int = 0
    output_tokens: int = 0
    elapsed_seconds: float = 0.0
    spend_usd: float = 0.0
    redaction_count: int = 0

    def as_document(self) -> dict:
        return {
            "schema_version": 1,
            "build_id": self.build_id,
            "provider": self.provider,
            "model": self.model,
            "limits": self.limits.as_evidence(),
            "totals": {
                "input_bytes": self.input_bytes,
                "input_tokens": self.input_tokens,
                "output_tokens": self.output_tokens,
                "elapsed_seconds": round(self.elapsed_seconds, 3),
                "spend_usd": round(self.spend_usd, 6),
                "redaction_count": self.redaction_count,
            },
            "attempts": self.attempts,
        }


def prompt_template_hash(template: str) -> str:
    """A stable identity for the prompt TEMPLATE. The template, never the filled prompt: the filled
    prompt contains source text, and this file must not carry source contents."""
    return hashlib.sha256(template.encode("utf-8")).hexdigest()


class AiBudget:
    """Enforces the bounds. ``check_before_call`` runs before every request, never after."""

    def __init__(self, limits: AiLimits, usage: AiUsage, *, clock=time.monotonic):
        self.limits = limits
        self.usage = usage
        self._clock = clock
        self._started = clock()

    def elapsed(self) -> float:
        return self._clock() - self._started

    def check_before_call(self, *, prompt_bytes: int, attempt: int) -> None:
        """Raise ``AiBudgetExhausted`` if this call would exceed any bound.

        Checked BEFORE the call because after is too late: the cost is already incurred and the
        model output already exists. Every bound is evaluated, so the error names the real reason.
        """
        if attempt > self.limits.max_attempts:
            raise AiBudgetExhausted(
                f"attempt {attempt} exceeds {MAX_ATTEMPTS_ENV}={self.limits.max_attempts}")
        elapsed = self.elapsed()
        if elapsed >= self.limits.max_wall_seconds:
            raise AiBudgetExhausted(
                f"drafting has used {elapsed:.1f}s of "
                f"{MAX_WALL_SECONDS_ENV}={self.limits.max_wall_seconds}")
        projected = self.usage.input_bytes + prompt_bytes
        if projected > self.limits.max_input_bytes:
            raise AiBudgetExhausted(
                f"this prompt would bring input to {projected}B, over "
                f"{MAX_INPUT_BYTES_ENV}={self.limits.max_input_bytes}")
        if (
            self.limits.spend_is_hard_cap
            and self.limits.max_spend_usd is not None
            and self.usage.spend_usd >= self.limits.max_spend_usd
        ):
            raise AiBudgetExhausted(
                f"spend {self.usage.spend_usd} has reached "
                f"{MAX_SPEND_USD_ENV}={self.limits.max_spend_usd}")

    def record_attempt(self, *, method: str, attempt: int, template_hash: str, prompt_bytes: int,
                       input_tokens: int, output_tokens: int, elapsed: float, result: str,
                       redactions: int = 0, spend_usd: float = 0.0) -> None:
        """Record one attempt. Deliberately takes counts and a hash — there is no parameter through
        which a raw prompt, source snippet, or credential could enter this record."""
        output_violation = output_tokens > self.limits.max_output_tokens
        recorded_result = "output-limit-violation" if output_violation else result
        self.usage.attempts.append({
            "method": method,
            "attempt": attempt,
            "prompt_template_sha256": template_hash,
            "input_bytes": prompt_bytes,
            "input_tokens": input_tokens,
            "output_tokens": output_tokens,
            "elapsed_seconds": round(elapsed, 3),
            "result": recorded_result,
            "redactions": redactions,
        })
        self.usage.input_bytes += prompt_bytes
        self.usage.input_tokens += input_tokens
        self.usage.output_tokens += output_tokens
        self.usage.elapsed_seconds += elapsed
        self.usage.spend_usd += spend_usd
        self.usage.redaction_count += redactions
        if output_violation:
            # The provider was asked to cap this and did not. Record the cost first, then fail
            # closed: otherwise the usage file would under-report the very response that violated
            # the limit.
            raise AiBudgetExhausted(
                f"provider returned {output_tokens} output tokens, over the requested "
                f"{MAX_OUTPUT_TOKENS_ENV}={self.limits.max_output_tokens}")


def write_ai_usage(path: str | Path, usage: AiUsage) -> tuple[Path, str]:
    """Write ``ai-usage.json`` canonically and return (path, sha256).

    The digest is what the release manifest carries, so the provenance is covered by the bundle
    approval rather than being an editable side file.
    """
    target = Path(path).expanduser()
    target.parent.mkdir(parents=True, exist_ok=True)
    body = json.dumps(usage.as_document(), sort_keys=True, indent=2, ensure_ascii=False) + "\n"
    target.write_text(body, encoding="utf-8")
    return target, hashlib.sha256(body.encode("utf-8")).hexdigest()
