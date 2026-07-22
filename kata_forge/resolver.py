"""Resolve and fetch a subnet's validator repo -- the input to auto-extract.

The primary entry is ``--repo <url|path>``: a local path is used in place (offline), a URL is
cloned into a work dir. Resolving a bare ``--subnet N`` needs a pluggable ``subnet -> repo``
hook (a static registry now; a Bittensor chain query later) -- absent one, it fails with a clear
message rather than guessing. Everything downstream reads the returned local path + pinned commit.
"""

from __future__ import annotations

import re
import subprocess
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

#: subnet number -> validator repo (url or path), or None if unknown.
SubnetResolver = Callable[[int], "str | None"]

#: Run a git argument list and return (returncode, stdout, stderr). Injectable for tests.
GitRunner = Callable[[list[str]], "tuple[int, str, str]"]


class RepoResolveError(Exception):
    """A validator repo could not be resolved or fetched."""


@dataclass(frozen=True)
class ResolvedRepo:
    """A fetched validator repo, pinned to a commit."""

    source: str  # the url or path given/resolved
    path: Path  # local filesystem path to read
    commit: str | None  # resolved HEAD sha (None if not a git repo)
    was_cloned: bool


def registry_resolver(mapping: dict[int, str]) -> SubnetResolver:
    """A static ``subnet -> repo`` resolver (until chain resolution exists)."""
    return lambda subnet: mapping.get(subnet)


def _run_git(args: list[str]) -> tuple[int, str, str]:
    completed = subprocess.run(["git", *args], capture_output=True, text=True)  # noqa: S603,S607
    return completed.returncode, completed.stdout.strip(), completed.stderr.strip()


def _git_head(git: GitRunner, path: Path) -> str | None:
    code, out, _ = git(["-C", str(path), "rev-parse", "HEAD"])
    return out or None if code == 0 else None


def _repo_dir_name(source: str) -> str:
    tail = source.rstrip("/").rsplit("/", 1)[-1]
    return re.sub(r"\.git$", "", tail) or "repo"


def resolve_repo(
    *,
    repo: str | None = None,
    subnet: int | None = None,
    commit: str | None = None,
    work_dir: str | Path | None = None,
    resolver: SubnetResolver | None = None,
    git_runner: GitRunner | None = None,
) -> ResolvedRepo:
    """Resolve ``--repo``/``--subnet`` to a local, commit-pinned validator repo."""
    git = git_runner or _run_git

    source = repo
    if source is None:
        if subnet is None:
            raise RepoResolveError("provide --repo <url|path> or --subnet N")
        if resolver is None:
            raise RepoResolveError(
                f"no subnet->repo resolver configured for subnet {subnet}; pass --repo <url|path>"
            )
        source = resolver(subnet)
        if not source:
            raise RepoResolveError(f"resolver returned no repo for subnet {subnet}")

    candidate = Path(source).expanduser()
    if candidate.exists() and candidate.is_dir():
        head = _git_head(git, candidate)
        if commit and head and head != commit:
            code, _, err = git(["-C", str(candidate), "checkout", commit])
            if code != 0:
                raise RepoResolveError(f"could not checkout {commit} in {candidate}: {err}")
            head = _git_head(git, candidate)
        return ResolvedRepo(source=source, path=candidate.resolve(), commit=head, was_cloned=False)

    # Treat as a remote URL -> clone.
    if work_dir is None:
        raise RepoResolveError(f"{source!r} is not a local dir and no work_dir was given to clone")
    dest = Path(work_dir).expanduser().resolve() / _repo_dir_name(source)
    if dest.exists() and any(dest.iterdir()):
        raise RepoResolveError(f"clone target {dest} already exists; remove it or use another work_dir")
    dest.parent.mkdir(parents=True, exist_ok=True)
    args = ["clone", source, str(dest)] if commit else ["clone", "--depth", "1", source, str(dest)]
    code, _, err = git(args)
    if code != 0:
        raise RepoResolveError(f"git clone {source} failed: {err}")
    if commit:
        code, _, err = git(["-C", str(dest), "checkout", commit])
        if code != 0:
            raise RepoResolveError(f"could not checkout {commit}: {err}")
    return ResolvedRepo(source=source, path=dest, commit=_git_head(git, dest), was_cloned=True)
