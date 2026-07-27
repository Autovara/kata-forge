"""License gate for vendoring (plan 7.1, S5).

Vendoring copies upstream source into a repository Kata ships. That is a licensing act, so it is
gated before the copy happens, not after: "license review before vendoring; incompatible/missing =>
CLONE or REFUSE".

The gate is deliberately conservative in one direction only. An UNRECOGNISED or MISSING license
blocks VENDOR but does not block CLONE — cloning and running upstream at a pinned commit is not
redistribution, so an unclear license is a reason not to copy, not a reason to refuse outright. A
license we can positively identify as copyleft blocks VENDOR explicitly rather than falling through
as "unknown", because that distinction is the one a reviewer most needs to see.

Detection is intentionally simple and evidence-producing: it reports WHICH file it read and WHAT it
matched, so a human can check the call rather than trusting a verdict. It is not a substitute for
legal review; it is a gate that refuses to proceed without one.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

#: Filenames that conventionally carry the license, in the order we prefer them.
_LICENSE_FILENAMES = ("LICENSE", "LICENSE.txt", "LICENSE.md", "LICENCE", "LICENCE.txt",
                      "COPYING", "COPYING.txt", "UNLICENSE")

#: Permissive licenses whose terms allow vendoring with attribution retained.
_VENDOR_OK = {
    "MIT": (r"\bMIT License\b", r"Permission is hereby granted, free of charge"),
    "BSD-3-Clause": (r"\bBSD 3-Clause\b", r"Redistributions of source code must retain"),
    "BSD-2-Clause": (r"\bBSD 2-Clause\b",),
    "Apache-2.0": (r"\bApache License\b.{0,40}Version 2\.0", r"www\.apache\.org/licenses/LICENSE-2\.0"),
    "ISC": (r"\bISC License\b",),
    "Unlicense": (r"\bThis is free and unencumbered software released into the public domain\b",),
}

#: Copyleft licenses. Not "unknown" — positively identified, and a hard VENDOR block.
_VENDOR_BLOCKED = {
    "GPL-3.0": (r"\bGNU GENERAL PUBLIC LICENSE\b.{0,60}Version 3",),
    "GPL-2.0": (r"\bGNU GENERAL PUBLIC LICENSE\b.{0,60}Version 2",),
    "AGPL-3.0": (r"\bGNU AFFERO GENERAL PUBLIC LICENSE\b",),
    "LGPL-3.0": (r"\bGNU LESSER GENERAL PUBLIC LICENSE\b",),
}


@dataclass(frozen=True)
class LicenseFinding:
    """What was found, where, and what it permits — the evidence a reviewer checks."""

    spdx: str | None          # e.g. "MIT"; None when nothing was recognised
    source_file: str | None   # repo-relative path actually read
    vendor_allowed: bool
    reason: str
    notes: list[str] = field(default_factory=list)

    def as_evidence(self) -> dict:
        return {"spdx": self.spdx, "source_file": self.source_file,
                "vendor_allowed": self.vendor_allowed, "reason": self.reason}


def _read_license_text(repo: Path) -> tuple[str | None, str | None]:
    for name in _LICENSE_FILENAMES:
        candidate = repo / name
        if candidate.is_file() and not candidate.is_symlink():
            try:
                return candidate.read_text(encoding="utf-8", errors="ignore"), name
            except OSError:
                continue
    return None, None


def detect_license(repo: str | Path) -> LicenseFinding:
    """Identify the upstream license and whether it permits vendoring."""
    root = Path(repo).expanduser()
    text, source_file = _read_license_text(root)
    if text is None:
        return LicenseFinding(
            spdx=None, source_file=None, vendor_allowed=False,
            reason="no LICENSE/COPYING file found; vendoring requires a reviewed license",
            notes=["CLONE remains possible: running upstream at a pinned commit is not redistribution"],
        )

    head = text[:8000]  # the identifying header; avoids scanning a huge appended notice file
    for spdx, patterns in _VENDOR_BLOCKED.items():
        if any(re.search(p, head, re.IGNORECASE | re.DOTALL) for p in patterns):
            return LicenseFinding(
                spdx=spdx, source_file=source_file, vendor_allowed=False,
                reason=f"{spdx} is copyleft; vendoring it into Kata is not permitted without review",
                notes=["CLONE at a pinned commit avoids redistribution"],
            )
    for spdx, patterns in _VENDOR_OK.items():
        if any(re.search(p, head, re.IGNORECASE | re.DOTALL) for p in patterns):
            return LicenseFinding(
                spdx=spdx, source_file=source_file, vendor_allowed=True,
                reason=f"{spdx} is permissive; vendoring is allowed with attribution retained",
            )
    return LicenseFinding(
        spdx=None, source_file=source_file, vendor_allowed=False,
        reason=f"license in {source_file} was not recognised; a human must classify it before vendoring",
        notes=["unrecognised is not the same as incompatible: CLONE remains available"],
    )
