"""No-credential and no-egress canaries (plan 7.4, S6).

A compartment policy is a claim. These are the experiments that test it: from inside each
compartment, deliberately attempt the things that must be impossible, and require every one of them
to FAIL.

Two properties, per the plan:

* **No credential is reachable.** Reading ``/srv/kata-bot/.env``, the builder's home, host SSH
  material, or any credential path must fail from every compartment.
* **No egress outside the Fetch allowlist.** Draft and Verify must have no network at all.

The single most important rule here is that **a canary which could not run is not a pass**. If the
host cannot build a compartment, that is an inconclusive result and must be reported as such — the
tempting failure mode is a probe that silently no-ops and returns "all clear", which would certify
exactly the unconfined execution this is meant to catch.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from kata_forge.compartment import (
    COMPARTMENTS,
    Compartment,
    CompartmentUnavailable,
    fresh_workspace,
    run_in_compartment,
)

#: Paths that must be unreachable from any compartment. Absolute and host-specific on purpose:
#: these are the real files whose disclosure would matter.
CREDENTIAL_PATHS: tuple[str, ...] = (
    "/srv/kata-bot/.env",              # GitHub token, webhook secret, provider keys
    "/srv/kata-subnets/registry.json",  # root-owned installer state
    "/srv/kata-subnets/approvals",      # approval records
    "/root/.ssh/id_rsa",
    "/home/ubuntu/.ssh/id_rsa",
    "/home/ubuntu/.gitconfig",          # may carry a credential helper / token
    "/etc/shadow",
)

#: Hosts a compartment must not be able to reach. Draft/Verify must fail on ALL of them; Fetch is
#: allowed HTTPS to GitHub and nothing else is asserted here (its allowlist is enforced by giving it
#: only git and by the canonical-URL gate upstream).
EGRESS_PROBES: tuple[tuple[str, int], ...] = (
    ("1.1.1.1", 443),
    ("8.8.8.8", 53),
)


@dataclass(frozen=True)
class CanaryResult:
    """One probe. ``blocked`` is the only acceptable outcome; ``inconclusive`` is never a pass."""

    compartment: str
    probe: str
    blocked: bool
    inconclusive: bool = False
    detail: str = ""

    @property
    def passed(self) -> bool:
        return self.blocked and not self.inconclusive


class CanaryFailure(Exception):
    """A canary reached something it must not, or could not be evaluated. Fail closed."""


def _probe_read(path: str) -> list[str]:
    """A command that exits 0 ONLY if the path was actually readable."""
    return ["/bin/sh", "-c", f'if [ -r "{path}" ] && head -c1 "{path}" >/dev/null 2>&1; '
                             f'then echo REACHED; exit 0; else exit 7; fi']


#: Interpreter used for the egress probe. NOT /bin/sh: on Debian/Ubuntu that is dash, which has no
#: /dev/tcp, so a shell-based connect probe fails identically whether or not the network is
#: reachable — it would report "blocked" for a fully connected compartment. A probe that cannot
#: observe the thing it tests is worse than no probe, because it certifies.
_PROBE_PYTHON = "/usr/bin/python3"


def _probe_connect(host: str, port: int) -> list[str]:
    """A command that exits 0 and prints REACHED ONLY if a TCP connection actually opened."""
    script = (
        "import socket, sys\n"
        "sock = socket.socket()\n"
        "sock.settimeout(5)\n"
        "try:\n"
        f"    sock.connect(({host!r}, {port}))\n"
        "except OSError:\n"
        "    sys.exit(7)\n"
        "print('REACHED')\n"
    )
    return [_PROBE_PYTHON, "-c", script]


def _run_probe(compartment: Compartment, probe_name: str, argv: list[str],
               workspace_root: str | Path) -> CanaryResult:
    workspace = fresh_workspace(workspace_root, f"canary-{compartment.name}")
    try:
        run = run_in_compartment(compartment, argv, workspace=workspace)
    except CompartmentUnavailable as exc:
        # INCONCLUSIVE, never a pass: an un-runnable probe proves nothing about isolation.
        return CanaryResult(compartment=compartment.name, probe=probe_name, blocked=False,
                            inconclusive=True, detail=str(exc))
    reached = run.returncode == 0 and "REACHED" in run.stdout
    return CanaryResult(compartment=compartment.name, probe=probe_name, blocked=not reached,
                        detail=(run.stdout or run.stderr).strip()[:200])


def run_credential_canaries(workspace_root: str | Path,
                            compartments=None) -> list[CanaryResult]:
    """Attempt to read every credential path from every compartment. All must be blocked."""
    targets = compartments if compartments is not None else list(COMPARTMENTS.values())
    results: list[CanaryResult] = []
    for compartment in targets:
        for path in CREDENTIAL_PATHS:
            results.append(_run_probe(compartment, f"read:{path}", _probe_read(path),
                                      workspace_root))
    return results


def run_egress_canaries(workspace_root: str | Path, compartments=None) -> list[CanaryResult]:
    """Attempt network egress from the NO-NETWORK compartments. All must be blocked.

    Fetch is excluded by design: it is the one compartment that legitimately has egress. Its
    restriction is upstream — it may only ever be handed a canonical public GitHub URL, and it runs
    only ``git``.
    """
    targets = compartments if compartments is not None else [
        c for c in COMPARTMENTS.values() if not c.network]
    results: list[CanaryResult] = []
    for compartment in targets:
        for host, port in EGRESS_PROBES:
            results.append(_run_probe(compartment, f"connect:{host}:{port}",
                                      _probe_connect(host, port), workspace_root))
    return results


def assert_all_canaries_blocked(results: list[CanaryResult]) -> None:
    """Raise unless every probe was positively blocked. An empty result set is itself a failure."""
    if not results:
        raise CanaryFailure("no canaries ran; an empty canary set cannot certify anything")
    inconclusive = [r for r in results if r.inconclusive]
    if inconclusive:
        raise CanaryFailure(
            f"{len(inconclusive)} canary/canaries could not be evaluated "
            f"({inconclusive[0].detail}); an un-runnable probe is not a pass")
    reached = [r for r in results if not r.blocked]
    if reached:
        detail = ", ".join(f"{r.compartment}:{r.probe}" for r in reached[:5])
        raise CanaryFailure(f"{len(reached)} canary/canaries REACHED a forbidden resource: {detail}")
