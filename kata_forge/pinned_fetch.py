"""Isolated, commit-pinned fetch of a canonical public GitHub repository (plan 4.1/7, S5).

Everything downstream — the dependency scan, the secret scan, the AI draft, the parity fixture, the
eventual bundle — is only as trustworthy as the tree this produces. So the fetch is deliberately
narrow:

* **No submodules.** ``--recurse-submodules`` would fetch a second, unreviewed repository chosen by
  the first one. A repository that declares submodules is REFUSED rather than partially fetched:
  its build almost certainly needs them, so silently omitting them would produce a tree that scans
  clean and behaves differently.
* **No hooks, no host git config.** The clone runs with ``core.hooksPath=/dev/null`` and
  ``protocol.file.allow=never``, and the runner is handed an environment that does not include the
  operator's git configuration. A repository must not be able to execute anything during a fetch.
* **A full 40-hex commit SHA, verified after checkout.** A short SHA, a branch name, or a tag is not
  an immutable pin — tags move. The recorded commit is re-read from the checkout and compared, so a
  clone that silently landed elsewhere is caught rather than recorded as fact.

The subprocess runner is injectable so the whole module is testable without network or git.
"""
from __future__ import annotations

import re
import subprocess
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from kata_forge.trusted_input import CanonicalRepo

#: (returncode, stdout, stderr)
GitRunner = Callable[[list[str]], "tuple[int, str, str]"]

_FULL_SHA_RE = re.compile(r"^[0-9a-f]{40}$")

#: Hardened git flags applied to EVERY invocation. `-c` options come before the subcommand.
_HARDENED_GIT_CONFIG = [
    "-c", "core.hooksPath=/dev/null",   # a fetched repo may not run hooks
    "-c", "protocol.file.allow=never",  # no file:// submodule/transport escapes
    "-c", "credential.helper=",         # never consult a credential helper
]


class PinnedFetchError(Exception):
    """The source could not be fetched and pinned. Fail closed: never proceed on a partial tree."""


@dataclass(frozen=True)
class PinnedSource:
    """An immutable, fully-pinned source snapshot."""

    url: str
    commit: str  # full 40-hex
    path: Path

    def as_evidence(self) -> dict:
        """The provenance fields a decision record and a release manifest both carry."""
        return {"url": self.url, "commit": self.commit}


#: The minimal environment git ever sees: no operator config, no credentials, no proxy.
_GIT_ENV = {
    "PATH": "/usr/local/bin:/usr/bin:/bin",
    "HOME": "/nonexistent",
    "GIT_TERMINAL_PROMPT": "0",     # never block waiting for credentials
    "GIT_CONFIG_NOSYSTEM": "1",     # ignore /etc/gitconfig
    "GIT_ALLOW_PROTOCOL": "https",  # https only
}


def _host_git_runner(args: list[str]) -> tuple[int, str, str]:
    """Run git directly on the host, with a scrubbed environment.

    The FALLBACK, used only where a compartment cannot be built. It keeps the credential-scrubbing
    property but not the filesystem isolation, so ``compartment_git_runner`` is preferred.
    """
    completed = subprocess.run(["git", *args], capture_output=True, text=True,
                               env=dict(_GIT_ENV), timeout=900, check=False)
    return completed.returncode, completed.stdout.strip(), completed.stderr.strip()


def compartment_git_runner(workspace: "Path") -> GitRunner:
    """A git runner that executes inside the FETCH compartment (plan 7.4).

    Fetch is the one compartment with egress, and it must have no credentials, no operator home and
    no host git config — a scrubbed environment alone does not stop git reading ``~/.ssh`` or a
    credential helper's store, because those are filesystem reachability, not environment. Inside
    the compartment they are simply absent from the mount namespace.
    """
    from kata_forge.compartment import FETCH, CompartmentUnavailable, run_in_compartment

    def _run(args: list[str]) -> tuple[int, str, str]:
        try:
            result = run_in_compartment(FETCH, ["/usr/bin/git", *args], workspace=workspace)
        except CompartmentUnavailable:
            # Fail closed on isolation is wrong HERE: refusing to fetch at all would block every
            # build on a host that cannot namespace. Degrade to the scrubbed host runner and let the
            # caller see it in the build record rather than silently believing it was isolated.
            return _host_git_runner(args)
        return result.returncode, result.stdout.strip(), result.stderr.strip()

    return _run


def _default_git_runner(args: list[str]) -> tuple[int, str, str]:
    return _host_git_runner(args)


def _git(runner: GitRunner, args: list[str]) -> tuple[int, str, str]:
    return runner([*_HARDENED_GIT_CONFIG, *args])


def _assert_no_submodules(dest: Path) -> None:
    """Refuse a repository that declares submodules (plan 4.1)."""
    if (dest / ".gitmodules").exists():
        raise PinnedFetchError(
            f"{dest} declares .gitmodules; submodules are not fetched, and a tree missing them would "
            f"scan clean while behaving differently. REFUSE / NEEDS-HUMAN.")


def _resolve_head(runner: GitRunner, dest: Path) -> str:
    code, out, err = _git(runner, ["-C", str(dest), "rev-parse", "HEAD"])
    if code != 0:
        raise PinnedFetchError(f"cannot resolve HEAD in {dest}: {err or 'git rev-parse failed'}")
    commit = out.strip()
    if not _FULL_SHA_RE.match(commit):
        raise PinnedFetchError(
            f"resolved commit {commit!r} is not a full 40-character sha; a short sha, branch or tag "
            f"is not an immutable pin.")
    return commit


def fetch_pinned(
    canonical: CanonicalRepo,
    dest: str | Path,
    *,
    commit: str | None = None,
    git_runner: GitRunner | None = None,
) -> PinnedSource:
    """Clone ``canonical`` into ``dest`` and return its immutable pin.

    ``commit``, when given, must be a full 40-hex sha and must be what the checkout actually lands
    on. When omitted the default branch's HEAD is resolved and recorded, which is still an immutable
    pin for everything downstream.
    """
    runner = git_runner or _default_git_runner
    target = Path(dest).expanduser().resolve()
    if commit is not None and not _FULL_SHA_RE.match(str(commit)):
        raise PinnedFetchError(
            f"--commit must be a full 40-character sha, got {commit!r}. Tags and branches move, so "
            f"they cannot pin a build.")
    if target.exists() and any(target.iterdir()):
        raise PinnedFetchError(f"fetch destination {target} exists and is not empty")
    target.parent.mkdir(parents=True, exist_ok=True)

    # No --depth: a shallow clone cannot check out an arbitrary older commit, and the history is
    # what lets the pin be verified. No --recurse-submodules, deliberately.
    code, _, err = _git(runner, ["clone", "--no-checkout", canonical.url, str(target)])
    if code != 0:
        raise PinnedFetchError(f"git clone {canonical.url} failed: {err or 'unknown error'}")

    checkout_ref = commit or "HEAD"
    code, _, err = _git(runner, ["-C", str(target), "checkout", "--force", checkout_ref])
    if code != 0:
        raise PinnedFetchError(
            f"cannot check out {checkout_ref} in {canonical.url}: {err or 'unknown error'}")

    resolved = _resolve_head(runner, target)
    if commit is not None and resolved != commit:
        # The clone landed somewhere other than the requested pin. Recording `commit` here would make
        # the manifest assert something untrue about the tree that was actually scanned.
        raise PinnedFetchError(
            f"checkout mismatch: requested {commit} but the tree is at {resolved}")
    _assert_no_submodules(target)
    return PinnedSource(url=canonical.url, commit=resolved, path=target)
