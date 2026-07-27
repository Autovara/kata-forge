"""Embedded-credential scan and redaction (plan 4.2 step 3, S5).

Two different things are called "secrets" in this pipeline, and conflating them causes the wrong
behaviour:

* ``secrets.extract_secrets`` finds the env-var NAMES a repo reads (``OPENAI_API_KEY``). That is a
  *requirement*, not a leak — it feeds the EnvSpec and the free/metered cost gate.
* This module finds credential VALUES committed into the source itself. That is a leak, and it is a
  hard REFUSE **before any AI input**, for two reasons: the credential would be transmitted to a
  model provider, and a repository that ships a live credential is not one to automate against.

Redaction is applied to everything that leaves this process — decision records, provenance, logs —
so that reporting a leak never repeats it. A finding says *where* and *what kind*, never the value.

The patterns are prefix-based on purpose. Entropy heuristics on source trees produce far too many
false positives (hashes, base64 test fixtures, UUIDs) to gate a pipeline on; an issuer prefix like
``ghp_`` or ``AKIA`` is a positive identification of a real credential format.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

#: (kind, compiled pattern). Each matches a credential FORMAT, not merely a high-entropy string.
_CREDENTIAL_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("github-pat", re.compile(r"\bghp_[A-Za-z0-9]{36}\b")),
    ("github-pat", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{60,}\b")),
    ("github-oauth", re.compile(r"\bgho_[A-Za-z0-9]{36}\b")),
    ("openai-key", re.compile(r"\bsk-[A-Za-z0-9]{20,}\b")),
    ("aws-access-key-id", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("slack-token", re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b")),
    ("google-api-key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
    ("private-key-block", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----")),
    ("bittensor-mnemonic", re.compile(r"\bmnemonic\s*[=:]\s*[\"'](?:\w+\s+){11,}\w+[\"']")),
)

#: Directories never worth scanning; they hold third-party or generated content.
_SKIP_DIRS = frozenset({".git", ".venv", "venv", "node_modules", "__pycache__", ".mypy_cache",
                        ".pytest_cache", ".ruff_cache", "dist", "build", ".tox"})

#: Files above this size are almost certainly data, not source, and scanning them is wasteful.
_MAX_SCAN_BYTES = 2_000_000

REDACTED = "[REDACTED]"


@dataclass(frozen=True)
class EmbeddedSecret:
    """A credential value found in the source. Carries location and kind, NEVER the value."""

    path: str      # repo-relative
    line: int
    kind: str
    preview: str   # already redacted

    def as_evidence(self) -> dict:
        return {"path": self.path, "line": self.line, "kind": self.kind, "preview": self.preview}


def redact(text: str) -> str:
    """Replace every recognised credential in ``text`` with a marker.

    Applied to anything leaving the process. Reporting a leak must never repeat it — a decision
    record is written to disk and read by tools that were not vetted to hold a live credential.
    """
    if not isinstance(text, str):
        return text
    for _kind, pattern in _CREDENTIAL_PATTERNS:
        text = pattern.sub(REDACTED, text)
    return text


def _iter_candidate_files(root: Path):
    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.is_symlink():
            continue
        if any(part in _SKIP_DIRS for part in path.relative_to(root).parts):
            continue
        try:
            if path.stat().st_size > _MAX_SCAN_BYTES:
                continue
        except OSError:
            continue
        yield path


def scan_embedded_secrets(repo: str | Path) -> list[EmbeddedSecret]:
    """Every embedded credential in ``repo``, sorted by location. Empty means none were found."""
    root = Path(repo).expanduser()
    findings: list[EmbeddedSecret] = []
    for path in _iter_candidate_files(root):
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        rel = str(path.relative_to(root)).replace("\\", "/")
        for line_number, line in enumerate(text.splitlines(), start=1):
            for kind, pattern in _CREDENTIAL_PATTERNS:
                match = pattern.search(line)
                if match is None:
                    continue
                findings.append(EmbeddedSecret(
                    path=rel,
                    line=line_number,
                    kind=kind,
                    # The surrounding line, redacted -- enough to locate it, never enough to use it.
                    preview=redact(line.strip())[:200],
                ))
    return findings
