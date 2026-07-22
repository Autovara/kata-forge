"""The subnet spec: the parametrization every generated ``kata-sn<N>`` derives from.

A spec is the small set of identifiers that distinguish one subnet plugin from another; every
generated file is a function of it. Validation is strict so a bad spec fails fast (before any
files are written) rather than producing a broken skeleton.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

# pack: ``sn<N>__<slug>`` (matches the platform's lanes/<pack>/ keying), e.g. ``sn126__poker44``.
_PACK_RE = re.compile(r"^sn(\d+)__([a-z0-9]+(?:_[a-z0-9]+)*)$")
# evaluator id: lowercase identifier the core resolves the plugin by, e.g. ``sn126_poker44``.
_EVALUATOR_RE = re.compile(r"^[a-z][a-z0-9_]*$")
_MODE_RE = re.compile(r"^[a-z][a-z0-9_]*$")


class SpecError(ValueError):
    """The provided subnet spec is invalid (bad number/pack/evaluator/mode)."""


@dataclass(frozen=True)
class SubnetSpec:
    """Everything a generated ``kata-sn<N>`` plugin is parametrized by."""

    subnet_number: int
    pack: str
    evaluator_id: str
    mode: str = "miner"
    name: str = ""  # display slug; derived from the pack when empty

    @property
    def slug(self) -> str:
        return self.name or self.pack.split("__", 1)[-1]

    @property
    def package(self) -> str:
        return f"kata_sn{self.subnet_number}"

    @property
    def repo_name(self) -> str:
        return f"kata-sn{self.subnet_number}"

    @property
    def base_name(self) -> str:
        # poker44 -> Poker44 ; my_subnet -> MySubnet  (base for Plugin/Problems/RawRun classes)
        return "".join(part.capitalize() for part in re.split(r"[-_]", self.slug) if part)

    @property
    def class_name(self) -> str:
        return f"{self.base_name}Plugin"  # Poker44Plugin

    @property
    def singleton(self) -> str:
        # poker44 -> POKER44_PLUGIN
        return re.sub(r"[-]", "_", self.slug).upper() + "_PLUGIN"

    @property
    def display_title(self) -> str:
        return self.slug.replace("_", " ").title()


def validate_spec(
    *, subnet_number: int, pack: str, evaluator_id: str, mode: str = "miner", name: str = ""
) -> SubnetSpec:
    """Build a :class:`SubnetSpec`, raising :class:`SpecError` on any invalid field."""
    if not isinstance(subnet_number, int) or subnet_number <= 0:
        raise SpecError(f"--subnet must be a positive integer, got {subnet_number!r}")
    pack_match = _PACK_RE.match(pack or "")
    if not pack_match:
        raise SpecError(f"--pack must look like sn<N>__<slug> (lowercase), got {pack!r}")
    if int(pack_match.group(1)) != subnet_number:
        raise SpecError(f"--pack {pack!r} must start with sn{subnet_number}__")
    if not _EVALUATOR_RE.match(evaluator_id or ""):
        raise SpecError(f"--evaluator must be a lowercase identifier, got {evaluator_id!r}")
    if not _MODE_RE.match(mode or ""):
        raise SpecError(f"--mode must be a lowercase identifier, got {mode!r}")
    if name and not re.fullmatch(r"[a-z0-9]+(?:_[a-z0-9]+)*", name):
        raise SpecError(f"--name must be a lowercase slug, got {name!r}")
    return SubnetSpec(
        subnet_number=subnet_number,
        pack=pack,
        evaluator_id=evaluator_id,
        mode=mode,
        name=name,
    )


def spec_from_args(args: object) -> SubnetSpec:
    """Build and validate a spec from a parsed argparse namespace."""
    return validate_spec(
        subnet_number=getattr(args, "subnet"),
        pack=getattr(args, "pack"),
        evaluator_id=getattr(args, "evaluator"),
        mode=getattr(args, "mode", "miner"),
        name=getattr(args, "name", "") or "",
    )
