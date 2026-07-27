"""Trusted input for the production build path (plan 4.1, S5).

The existing ``resolver.resolve_repo`` is deliberately permissive: it accepts a local directory so a
developer can research a checkout offline. The production path must NOT inherit that behaviour — the
plan says so outright — because "whatever this path resolves to" is what later gets cloned, read by
an AI, scaffolded into a plugin, and eventually installed. So this module is the strict counterpart:

* ``--repo`` accepts exactly one shape: ``https://github.com/<owner>/<repo>``. Anything else —
  SSH, ``file:``, a local path, a redirect host, user-info, a query, an IP literal, three path
  segments — is REFUSED rather than normalised into something plausible.
* ``--subnet N`` resolves ONLY through a versioned local catalog, and only when exactly one entry
  matches. It never consults the chain, a search result, or a repository name. Guessing here would
  mean fetching and eventually installing an attacker-chosen repository.
* The two are mutually exclusive, so there is never an ambiguous precedence question.

Every refusal names the fix (``pass --repo <validator-url>``), because the failure mode this guards
against is an operator working around an unclear error by hand.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

#: GitHub's own rules: 1-39 chars, alphanumeric or hyphen, no leading/trailing/double hyphen.
_OWNER_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9]|-(?=[A-Za-z0-9])){0,38}$")
#: Repository names additionally allow dot and underscore. A LEADING HYPHEN is rejected: the name is
#: used as a directory name downstream, and an argument beginning with "-" is read as a flag by most
#: tools. A leading dot IS allowed, because ``owner/.github`` is a real and common repository.
_REPO_RE = re.compile(r"^[A-Za-z0-9._][A-Za-z0-9._-]{0,99}$")
CATALOG_SCHEMA_VERSION = 1


class TrustedInputError(Exception):
    """The input is not a canonical public GitHub repository, or the catalog cannot resolve it.

    Always a REFUSAL, never a fallback: the caller must not proceed with a guessed source.
    """


@dataclass(frozen=True)
class CanonicalRepo:
    """One canonical public GitHub repository."""

    owner: str
    repo: str

    @property
    def url(self) -> str:
        """The single normalized spelling stored in every record."""
        return f"https://github.com/{self.owner}/{self.repo}"

    @property
    def identity(self) -> str:
        """Lowercase comparison identity. GitHub treats owner/repo case-insensitively, so
        ``Owner/Repo`` and ``owner/repo`` are the SAME repository and must not be able to appear as
        two catalog entries or two distinct lanes."""
        return f"{self.owner.lower()}/{self.repo.lower()}"


def parse_canonical_github_url(raw: object) -> CanonicalRepo:
    """Parse a canonical public GitHub HTTPS URL, or refuse.

    Deliberately strict about things a lenient parser would accept and normalise:
    ``user:pass@`` (credential smuggling), ``?`` / ``#`` (a URL that reads differently to git than
    to a human), a non-github.com host, an IP literal, an explicit port, and any path that is not
    exactly two non-empty segments.
    """
    if not isinstance(raw, str) or not raw.strip():
        raise TrustedInputError("repository URL must be a non-empty string")
    value = raw.strip()
    if value != raw.strip().rstrip("/"):
        value = value.rstrip("/")

    try:
        parts = urlsplit(value)
    except ValueError as exc:
        raise TrustedInputError(f"unparseable repository URL {raw!r}: {exc}") from exc

    if parts.scheme != "https":
        raise TrustedInputError(
            f"repository URL must use https (got {parts.scheme or 'no'} scheme): {raw!r}. "
            f"SSH, git:// and file: sources are outside this automation's scope.")
    if parts.username or parts.password or "@" in parts.netloc:
        raise TrustedInputError(f"repository URL must not contain user-info: {raw!r}")
    if parts.query or parts.fragment:
        raise TrustedInputError(f"repository URL must have no query or fragment: {raw!r}")
    if parts.netloc.lower() != "github.com":
        raise TrustedInputError(
            f"only canonical public github.com URLs are accepted, got host "
            f"{parts.netloc!r}: {raw!r}. A private or non-GitHub source is REFUSE / NEEDS-HUMAN.")

    segments = [segment for segment in parts.path.split("/") if segment != ""]
    if len(segments) != 2:
        raise TrustedInputError(
            f"repository URL must have exactly two path segments (owner/repo), got {segments}: {raw!r}")
    owner, repo = segments
    repo = repo.removesuffix(".git")
    if repo in ("", ".", ".."):
        raise TrustedInputError(f"invalid repository name in {raw!r}")
    if ".." in repo or ".." in owner:
        # No real GitHub name contains "..", and the value becomes a directory name downstream.
        raise TrustedInputError(f"repository name must not contain '..': {raw!r}")
    if not _OWNER_RE.match(owner):
        raise TrustedInputError(f"invalid GitHub owner {owner!r} in {raw!r}")
    if not _REPO_RE.match(repo):
        raise TrustedInputError(f"invalid GitHub repository name {repo!r} in {raw!r}")
    return CanonicalRepo(owner=owner, repo=repo)


def load_subnet_catalog(path: str | Path) -> list[dict]:
    """Load and schema-validate the local subnet catalog.

    This is an input-DISCOVERY artifact, not the installed-lanes registry: it only answers "which
    repository does subnet N mean". A malformed catalog refuses rather than degrading to a partial
    lookup, since a partial lookup is exactly how a wrong repo would be selected.
    """
    catalog_path = Path(path).expanduser()
    try:
        raw = catalog_path.read_text(encoding="utf-8")
    except OSError as exc:
        raise TrustedInputError(f"cannot read subnet catalog {catalog_path}: {exc}") from exc
    try:
        document = json.loads(raw)
    except ValueError as exc:
        raise TrustedInputError(f"invalid JSON in subnet catalog {catalog_path}: {exc}") from exc
    if not isinstance(document, dict):
        raise TrustedInputError(f"subnet catalog {catalog_path} is not a JSON object")
    if document.get("schema_version") != CATALOG_SCHEMA_VERSION:
        raise TrustedInputError(
            f"subnet catalog schema_version {document.get('schema_version')!r} is not "
            f"{CATALOG_SCHEMA_VERSION}")
    entries = document.get("subnets")
    if not isinstance(entries, list):
        raise TrustedInputError(f"subnet catalog {catalog_path} has no 'subnets' list")

    seen: set[int] = set()
    for index, entry in enumerate(entries):
        where = f"{catalog_path}:subnets[{index}]"
        if not isinstance(entry, dict):
            raise TrustedInputError(f"{where} is not an object")
        subnet_id = entry.get("subnet_id")
        if isinstance(subnet_id, bool) or not isinstance(subnet_id, int) or subnet_id <= 0:
            raise TrustedInputError(f"{where}.subnet_id must be a positive int, got {subnet_id!r}")
        if subnet_id in seen:
            # Refuse the WHOLE catalog, not just this row: a duplicate means the operator's intent is
            # genuinely ambiguous, and silently taking either one could fetch the wrong repository.
            raise TrustedInputError(
                f"{where}: duplicate subnet_id {subnet_id} in the catalog; the entry is ambiguous. "
                f"Fix the catalog or pass --repo <validator-url>.")
        seen.add(subnet_id)
        parse_canonical_github_url(entry.get("validator_repo"))  # every row must be canonical
    return entries


def resolve_subnet(subnet_id: int, catalog_path: str | Path) -> CanonicalRepo:
    """The single canonical repo for ``subnet_id``, or a refusal naming the ``--repo`` escape hatch."""
    if isinstance(subnet_id, bool) or not isinstance(subnet_id, int) or subnet_id <= 0:
        raise TrustedInputError(f"--subnet must be a positive integer, got {subnet_id!r}")
    matches = [entry for entry in load_subnet_catalog(catalog_path)
               if entry.get("subnet_id") == subnet_id]
    if not matches:
        raise TrustedInputError(
            f"subnet {subnet_id} is not in the catalog. This command never guesses a repository "
            f"from the chain, a search result, or a repository name — pass --repo <validator-url>.")
    if len(matches) > 1:  # defence in depth: load_subnet_catalog already rejects duplicates
        raise TrustedInputError(
            f"subnet {subnet_id} matches {len(matches)} catalog entries; pass --repo <validator-url>.")
    return parse_canonical_github_url(matches[0]["validator_repo"])


def resolve_trusted_input(
    *, repo: object = None, subnet: object = None, catalog_path: str | Path | None = None
) -> CanonicalRepo:
    """Resolve the production build input from exactly one of ``--repo`` or ``--subnet``."""
    if repo is not None and subnet is not None:
        raise TrustedInputError("--repo and --subnet are mutually exclusive; pass exactly one")
    if repo is not None:
        return parse_canonical_github_url(repo)
    if subnet is not None:
        if catalog_path is None:
            raise TrustedInputError(
                "--subnet requires a local subnet catalog; pass --repo <validator-url> instead")
        return resolve_subnet(subnet, catalog_path)
    raise TrustedInputError("provide exactly one of --repo <validator-url> or --subnet <N>")
