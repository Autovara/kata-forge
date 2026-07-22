"""Optional, opt-in LLM draft seam for the four stub method bodies.

Off by default and **never required**: the deterministic map (deps + anchors + cost + report) is
the value; this only turns the anchors into a first draft a human reviews. It is a *seam* -- a
pluggable ``LlmDrafter`` -- not a wired provider. Enable by setting ``KATA_FORGE_LLM=<provider>``
(and that provider's key) and supplying a drafter; unset, ``--llm`` prints a clear "seam not wired"
note and the scaffold is written exactly as it would be without the flag. Any draft is injected as
a *comment* only, so an unavailable or wrong draft can never break the generated code.
"""

from __future__ import annotations

import os
from collections.abc import Callable

from kata_forge.anchors import Anchor
from kata_forge.spec import SubnetSpec

#: prompt -> drafted text. Injected so a provider can be plugged without touching kata-forge.
LlmDrafter = Callable[[str], str]

_ENV_FLAG = "KATA_FORGE_LLM"  # provider id (e.g. "anthropic"); off unless set


class LlmUnavailable(Exception):
    """The LLM draft seam is not wired/enabled (never fatal -- scaffolding proceeds without it)."""


def llm_enabled() -> bool:
    return bool(os.environ.get(_ENV_FLAG))


def build_prompt(method: str, anchor: Anchor | None, spec: SubnetSpec) -> str:
    """A draft prompt for one stub, grounded in its source anchor."""
    source = (
        f"{anchor.file}:{anchor.lineno} {anchor.symbol} ({anchor.detail})"
        if anchor is not None
        else "(no source anchor found -- infer from the subnet's contract)"
    )
    return (
        f"Draft the body of {spec.class_name}.{method} for the kata subnet plugin {spec.pack}. "
        f"Port the logic from the validator source {source}. Return Python only, no prose."
    )


def default_drafter() -> LlmDrafter:
    """The default drafter: provider-gated, and a documented seam rather than a wired provider.

    It intentionally raises :class:`LlmUnavailable` unless a provider *and* a concrete drafter are
    configured -- the value of M4 is the deterministic map; wiring a real provider is a deliberate,
    opt-in follow-up (supply a drafter to ``write_extract(drafter=...)``).
    """
    provider = os.environ.get(_ENV_FLAG)
    if not provider:
        raise LlmUnavailable(
            f"set {_ENV_FLAG}=<provider> and the provider API key to enable --llm drafting"
        )
    raise LlmUnavailable(
        f"--llm provider {provider!r} has no drafter wired; pass one via write_extract(drafter=...)"
    )
