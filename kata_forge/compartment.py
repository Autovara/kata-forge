"""The Fetch / Draft / Verify OS compartments (plan 7.4, S6).

Three different kinds of untrusted work happen during a build, and they must not share a blast
radius:

* **Fetch** runs ``git`` against a canonical public URL. It needs HTTPS out; it must never see a
  credential, the operator's home, or host git config.
* **Draft** runs an AI CLI over a read-only source snapshot. It needs NO network at all — it is the
  step most likely to exfiltrate, whether by prompt injection in the fetched source or by a model
  deciding to be helpful.
* **Verify** executes untrusted plugin and upstream code. It gets no network and no credentials, and
  its only writable surface is a disposable result directory.

Each compartment is one ``bwrap`` invocation: a fresh mount namespace where the base filesystem is
read-only, ``/srv``, ``/home`` and ``/etc`` credential material are simply ABSENT rather than merely
unreadable, the process runs as a non-root uid with no capabilities, and rlimits bound CPU, memory,
process count and file size. A wall-clock timeout bounds the rest.

**On privilege.** Creating the namespace needs root on a host with
``kernel.apparmor_restrict_unprivileged_userns=1`` (the Ubuntu 24.04 default), so the *launcher* is
root while the *workload* is uid 65534 with no capabilities. That is the same shape as the S4
installer: root sets up a jail, the untrusted thing runs inside it unprivileged.

``build_argv`` is a pure function so the policy can be asserted anywhere; ``run_in_compartment``
needs a host that can actually create the namespace.
"""
from __future__ import annotations

import os
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

BWRAP = os.environ.get("KATA_FORGE_BWRAP", "/usr/bin/bwrap")
SUDO = os.environ.get("KATA_FORGE_SUDO", "/usr/bin/sudo")

#: nobody/nogroup. The workload owns nothing on the host.
SANDBOX_UID = 65534
SANDBOX_GID = 65534

#: Read-only system paths every compartment needs to run a binary at all. Deliberately minimal:
#: /srv, /home, /root and /etc are NOT here, so credential material is absent from the mount
#: namespace rather than present-but-unreadable.
_BASE_RO_PATHS = ("/usr", "/bin", "/sbin", "/lib", "/lib64")

#: The only environment any compartment ever sees. A fresh dict, not a filtered copy of os.environ:
#: a filter leaks whatever it forgot, and what it would forget is exactly the new credential var.
CLEAN_ENV = {
    "PATH": "/usr/local/bin:/usr/bin:/bin",
    "HOME": "/tmp",
    "LC_ALL": "C.UTF-8",
    "GIT_TERMINAL_PROMPT": "0",
    "GIT_CONFIG_NOSYSTEM": "1",
}


class CompartmentError(Exception):
    """The compartment could not be constructed or run. Fail closed: never fall back to the host."""


class CompartmentUnavailable(CompartmentError):
    """This host cannot create the namespace. NOT a pass: work must not silently run unconfined."""


@dataclass(frozen=True)
class Compartment:
    """One isolation policy."""

    name: str
    network: bool                  # Fetch only
    #: Absolute host paths mounted read-only IN ADDITION to the minimal base.
    ro_paths: tuple[str, ...] = ()
    #: Wall-clock ceiling for the whole invocation.
    max_wall_seconds: int = 900
    max_memory_bytes: int = 2 * 1024**3
    max_processes: int = 512
    max_file_bytes: int = 512 * 1024**2
    #: Whether the workload may execute code that came from the fetched source.
    may_execute_untrusted: bool = False
    notes: tuple[str, ...] = field(default_factory=tuple)


FETCH = Compartment(
    name="fetch",
    network=True,  # the ONLY compartment with egress, and only for HTTPS to GitHub
    max_wall_seconds=900,
    notes=("git only; no project hooks or submodules; no credentials, home, or host git config",),
)

DRAFT = Compartment(
    name="draft",
    network=False,  # an AI step with egress is an exfiltration path; it has none
    max_wall_seconds=1800,
    notes=("AI CLI and static format/lint tools; never executes source-project code",),
)

VERIFY = Compartment(
    name="verify",
    network=False,
    max_wall_seconds=1800,
    may_execute_untrusted=True,
    notes=("runs untrusted plugin/upstream/test code as the sandbox uid; tests use fakes",),
)

COMPARTMENTS = {c.name: c for c in (FETCH, DRAFT, VERIFY)}


def available() -> bool:
    """Whether this host can actually build a compartment."""
    return Path(BWRAP).exists()


def build_argv(
    compartment: Compartment,
    argv: list[str],
    *,
    workspace: str | Path,
    ro_extra: tuple[str, ...] = (),
    as_root_launcher: bool = True,
) -> list[str]:
    """The exact command that runs ``argv`` inside ``compartment``. Pure: no side effects.

    ``workspace`` is the ONLY writable path. It is bound at the same location inside, so paths in
    the workload's output stay meaningful to the caller.
    """
    if not argv:
        raise CompartmentError("no command given to run in the compartment")
    work = Path(workspace).expanduser().resolve()

    command: list[str] = []
    if as_root_launcher:
        # Root creates the namespace; the workload inside is uid 65534 with no capabilities.
        command += [SUDO, "-n"]
    command += [BWRAP]

    for path in _BASE_RO_PATHS:
        if Path(path).exists():
            command += ["--ro-bind", path, path]

    # ORDER MATTERS: bwrap applies mounts in argument order, so the /tmp tmpfs is set up BEFORE any
    # caller-supplied path. Reversed, the tmpfs overlays anything living under /tmp -- a workspace
    # from mkdtemp, or a read-only build-tools fixture -- and the workload sees an empty directory
    # instead, with no error. Both classes of caller path therefore come after it.
    command += ["--proc", "/proc", "--dev", "/dev", "--tmpfs", "/tmp"]

    for path in (*compartment.ro_paths, *ro_extra):
        resolved = Path(path).expanduser().resolve()
        if not resolved.exists():
            raise CompartmentError(f"read-only input does not exist: {resolved}")
        command += ["--ro-bind", str(resolved), str(resolved)]

    command += [
        "--bind", str(work), str(work),   # the single writable surface
        "--chdir", str(work),
        "--unshare-user",
        "--uid", str(SANDBOX_UID),
        "--gid", str(SANDBOX_GID),
        "--unshare-pid",
        "--unshare-ipc",
        "--unshare-uts",
        "--unshare-cgroup",
        "--new-session",        # no terminal to inject into
        "--die-with-parent",
        "--cap-drop", "ALL",
    ]
    if not compartment.network:
        command += ["--unshare-net"]
    return [*command, "--", *argv]


def _apply_rlimits(compartment: Compartment):
    """A preexec hook applying the compartment's resource ceilings to the launched process."""
    def _limits() -> None:  # pragma: no cover - runs in the forked child
        import resource

        resource.setrlimit(resource.RLIMIT_AS,
                           (compartment.max_memory_bytes, compartment.max_memory_bytes))
        resource.setrlimit(resource.RLIMIT_NPROC,
                           (compartment.max_processes, compartment.max_processes))
        resource.setrlimit(resource.RLIMIT_FSIZE,
                           (compartment.max_file_bytes, compartment.max_file_bytes))
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))  # no core dumps of untrusted memory
    return _limits


@dataclass(frozen=True)
class CompartmentRun:
    """A captured result. Logs are captured, never streamed to the operator's terminal."""

    compartment: str
    returncode: int
    stdout: str
    stderr: str
    timed_out: bool = False

    @property
    def ok(self) -> bool:
        return self.returncode == 0 and not self.timed_out


def run_in_compartment(
    compartment: Compartment,
    argv: list[str],
    *,
    workspace: str | Path,
    ro_extra: tuple[str, ...] = (),
    as_root_launcher: bool = True,
) -> CompartmentRun:
    """Run ``argv`` inside ``compartment``. Raises CompartmentUnavailable if the host cannot isolate.

    Never falls back to running unconfined: a build step that could not be isolated has not been
    verified, and reporting it as a pass is the failure this whole section exists to prevent.
    """
    if not available():
        raise CompartmentUnavailable(
            f"{BWRAP} is not present; refusing to run {compartment.name} work unconfined")
    work = Path(workspace).expanduser().resolve()
    work.mkdir(parents=True, exist_ok=True)
    command = build_argv(compartment, argv, workspace=work, ro_extra=ro_extra,
                         as_root_launcher=as_root_launcher)
    try:
        completed = subprocess.run(
            command, capture_output=True, text=True, env=dict(CLEAN_ENV),
            timeout=compartment.max_wall_seconds, check=False,
            preexec_fn=_apply_rlimits(compartment),  # noqa: PLW1509 - bounding untrusted work
        )
    except subprocess.TimeoutExpired:
        return CompartmentRun(compartment=compartment.name, returncode=124, stdout="",
                              stderr=f"timed out after {compartment.max_wall_seconds}s",
                              timed_out=True)
    except OSError as exc:
        raise CompartmentUnavailable(f"cannot launch the {compartment.name} compartment: {exc}") from exc

    stderr = completed.stderr or ""
    if completed.returncode != 0 and "setting up uid map" in stderr:
        raise CompartmentUnavailable(
            "cannot create a user namespace (kernel.apparmor_restrict_unprivileged_userns=1). The "
            "compartment launcher must run as root; refusing to run unconfined.")
    if completed.returncode != 0 and "Can't find source path" in stderr:
        raise CompartmentUnavailable(
            f"bwrap could not resolve a bind source ({stderr.strip()}). bwrap resolves bind sources "
            f"AFTER dropping privileges, so every ancestor of {work} must be searchable by the "
            f"sandbox uid — use fresh_workspace(), which arranges that.")
    return CompartmentRun(compartment=compartment.name, returncode=completed.returncode,
                          stdout=completed.stdout, stderr=completed.stderr)


def _ensure_traversable(path: Path, stop_at: Path = Path("/tmp")) -> None:
    """Give the sandbox uid SEARCH permission on every ancestor up to ``stop_at``.

    Necessary because ``bwrap`` resolves ``--bind`` source paths AFTER dropping to the unprivileged
    uid — deliberately, to avoid acting as a confused deputy for the caller. The practical
    consequence is that a workspace under a ``0700`` directory (which is what ``mkdtemp`` and
    pytest's ``tmp_path`` both create) fails with "Can't find source path: Permission denied" even
    when the launcher is root.

    Only ``o+x`` is added, never ``o+r``: ancestors become traversable, not listable. The walk stops
    at ``stop_at`` so this can never wander up into ``/home`` or ``/``.
    """
    stop = stop_at.resolve()
    current = path.resolve()
    while current != stop and stop in current.parents:
        try:
            mode = current.stat().st_mode & 0o777
            if not mode & 0o001:
                current.chmod(mode | 0o001)
        except OSError:
            return  # not ours to change; run_in_compartment will surface the real error
        current = current.parent


def fresh_workspace(root: str | Path, name: str) -> Path:
    """A disposable, empty workspace. Recreated per run so no state survives between builds."""
    workspace = Path(root).expanduser().resolve() / name
    shutil.rmtree(workspace, ignore_errors=True)
    workspace.mkdir(parents=True)
    workspace.chmod(0o777)  # the sandbox uid (65534) must be able to write here
    _ensure_traversable(workspace)
    return workspace
