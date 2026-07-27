"""``kata-forge build`` — the one-command, non-root, transactional chain (plan 4.2, S7).

This is the command the whole plan is written around: point it at a canonical validator repository
and it emits ONE immutable, reviewable release bundle. It never writes ``/srv``, never renders a
unit, never touches service state, and never runs as root. Everything privileged happens later,
behind the human approval in §3.8.

Three properties do the heavy lifting:

**Content-addressed identity.** ``build-id`` is the SHA-256 of a canonical ``BuildInputs`` document —
the input URL, the resolved upstream commit, the pinned kata/kata-bot/kata-forge revisions, the
policy version, and an explicit attempt nonce. Same inputs, same id. That is what makes a retry
idempotent rather than a fresh spend, and what makes ``--new-attempt`` an explicit, auditable act
rather than a silent rebuild.

**Transactional emission.** Everything is written into a staging directory on the same filesystem,
validated there, fsynced, and only then atomically renamed to the immutable ``<build-id>``. A crash
leaves staging debris that is never installable — there is no window in which a half-written bundle
looks complete. There is deliberately no ``--force``.

**Honest state.** ``build-state.json`` records only where the build got to. A build that did not
reach ``verified`` cannot be staged: the S4 installer rejects it before promotion, so "the build
crashed" can never be mistaken for "the build passed".
"""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import stat
from dataclasses import dataclass, field
from pathlib import Path

from kata_forge.compartment import VERIFY, CompartmentUnavailable, fresh_workspace, run_in_compartment
from kata_forge.decision import REFUSE, DecisionInputs, decide, write_decision_record
from kata_forge.onboard import INTEGRATION_DECISION_FILENAME
from kata_forge.cost import estimate_cost
from kata_forge.deps import classify_repo
from kata_forge.license_gate import detect_license
from kata_forge.pinned_fetch import fetch_pinned
from kata_forge.redaction import scan_embedded_secrets
from kata_forge.trusted_input import (
    CanonicalRepo,
    TrustedInputError,
    resolve_trusted_input,
)

POLICY_VERSION = "s7.v1"
BUILD_STATE_FILENAME = "build-state.json"
MANIFEST_FILENAME = "release-manifest.json"
SBOM_FILENAME = "sbom.json"
OUTPUT_ROOT_ENV = "KATA_FORGE_OUTPUT_ROOT"
#: The interpreter that exists INSIDE a compartment (only /usr, /bin, /lib are bound).
COMPARTMENT_PYTHON = "/usr/bin/python3"
#: A PINNED, OFFLINE build-tools environment (hatchling/setuptools/wheel), bound READ-ONLY into the
#: Verify compartment. Every real Kata plugin builds with hatchling, which the system python does not
#: ship -- and the compartment has no network, by design, so it cannot fetch one. Providing the
#: toolchain as a read-only fixture is what plan 7.4 means by "fixtures read-only".
BUILD_TOOLS_ENV = os.environ.get("KATA_FORGE_BUILD_TOOLS", "/opt/kata-forge/build-tools")

#: The only states a build may record (plan 4.2). Anything else is a bug, not a new state.
STATES = ("researching", "drafting", "verifying", "verified", "refused", "failed")

#: Paths a build output root may never live under: writing build intermediates into live state is
#: precisely the "build is not deployment" boundary this command exists to hold.
_FORBIDDEN_ROOTS = ("/srv", "/etc", "/usr", "/boot", "/var/lib")


class BuildError(Exception):
    """The build cannot proceed. Nothing installable is produced."""


class BuildRefused(BuildError):
    """REFUSE / NEEDS-HUMAN. A recorded, reviewable outcome — not a crash."""


@dataclass(frozen=True)
class BuildInputs:
    """Everything that determines the build identity. Canonical and fully ordered."""

    source_url: str
    source_commit: str
    kata_rev: str
    kata_bot_rev: str
    kata_forge_rev: str
    policy_version: str = POLICY_VERSION
    attempt_nonce: str = "1"

    def canonical(self) -> dict:
        return {
            "source_url": self.source_url,
            "source_commit": self.source_commit,
            "kata_rev": self.kata_rev,
            "kata_bot_rev": self.kata_bot_rev,
            "kata_forge_rev": self.kata_forge_rev,
            "policy_version": self.policy_version,
            "attempt_nonce": self.attempt_nonce,
        }

    def build_id(self) -> str:
        body = json.dumps(self.canonical(), sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(body.encode("utf-8")).hexdigest()


def validate_output_root(path: str | Path) -> Path:
    """The output root must be an absolute, private directory the invoking user owns.

    ``0700`` and ownership matter because the staging tree briefly holds the fetched source and the
    drafted plugin; a group- or world-writable root would let another account swap either between
    validation and the atomic rename.
    """
    root = Path(path).expanduser()
    if not root.is_absolute():
        raise BuildError(f"{OUTPUT_ROOT_ENV} must be an absolute path, got {path!r}")
    resolved = root.resolve()
    for forbidden in _FORBIDDEN_ROOTS:
        if resolved == Path(forbidden) or str(resolved).startswith(forbidden + "/"):
            raise BuildError(
                f"output root {resolved} is inside {forbidden}; a build must never write live state")
    if not resolved.is_dir():
        raise BuildError(f"output root {resolved} does not exist (create it mode 0700)")
    info = resolved.stat()
    if info.st_uid != os.getuid():
        raise BuildError(f"output root {resolved} is not owned by the invoking user")
    if info.st_mode & (stat.S_IRWXG | stat.S_IRWXO):
        raise BuildError(
            f"output root {resolved} is group/other accessible; it must be mode 0700 so the staging "
            f"tree cannot be swapped between validation and promotion")
    if os.geteuid() == 0:
        raise BuildError("build must not run as root; it produces an unprivileged bundle only")
    return resolved


@dataclass
class BuildState:
    """The durable record of where a build got to. Deliberately tiny."""

    build_id: str
    state: str = "researching"
    phase: str = "preflight"
    reason: str = ""
    #: Pins the S4 installer cross-checks against the manifest.
    plugin_contract_version: int = 0
    evaluator_id: str = ""
    kata_tree_hash: str = ""
    conformance: str = "not-run"
    #: Methods still unwritten. A non-empty list is an honest UNRESOLVED build: emitted
    #: for review, but refused by the trusted installer.
    unresolved_methods: list = None

    def as_document(self) -> dict:
        if self.state not in STATES:
            raise BuildError(f"illegal build state {self.state!r}")
        return {
            "schema_version": 1,
            "build_id": self.build_id,
            "state": self.state,
            "phase": self.phase,
            "reason": self.reason,
            "plugin_contract_version": self.plugin_contract_version,
            "evaluator_id": self.evaluator_id,
            "kata_tree_hash": self.kata_tree_hash,
            "conformance": self.conformance,
            "unresolved_methods": sorted(self.unresolved_methods or []),
        }


def _fsync_write(path: Path, body: str) -> None:
    """Write and fsync, then fsync the parent. A build-state that survives a crash is the whole
    point of recording one."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(body)
        handle.flush()
        os.fsync(handle.fileno())
    dir_fd = os.open(path.parent, os.O_DIRECTORY)
    try:
        os.fsync(dir_fd)
    finally:
        os.close(dir_fd)


def _canonical_json(document: dict) -> str:
    return json.dumps(document, sort_keys=True, indent=2, ensure_ascii=False) + "\n"


def write_build_state(root: Path, state: BuildState) -> None:
    _fsync_write(root / BUILD_STATE_FILENAME, _canonical_json(state.as_document()))


def read_build_state(root: Path) -> dict | None:
    try:
        return json.loads((root / BUILD_STATE_FILENAME).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


# ---- SBOM ----------------------------------------------------------------------------------------
def build_sbom(source_root: Path, pinned_url: str, pinned_commit: str) -> dict:
    """A minimal, deterministic SBOM: the pinned upstream plus every declared dependency.

    Deterministic on purpose — it lands in the tree manifest, so a nondeterministic SBOM would change
    the bundle digest between identical builds and break idempotence.
    """
    report = classify_repo(source_root)
    components = sorted({
        *report.free, *report.gpu, *report.paid_api, *report.gated_data, *report.unclassified,
    })
    return {
        "schema_version": 1,
        "source": {"url": pinned_url, "commit": pinned_commit},
        "components": [{"name": name, "type": "python-package"} for name in components],
        "dependency_sources": sorted(report.sources),
    }



def read_unresolved_methods(plugin_tree: Path) -> list[str]:
    """The methods a scaffolded plugin still declares as unwritten.

    Parsed from the source with ast, never imported: importing generated plugin code inside the
    build process is precisely what the Draft/Verify compartments exist to prevent.
    """
    import ast

    for module in sorted(plugin_tree.rglob("plugin.py")):
        try:
            tree = ast.parse(module.read_text(encoding="utf-8"))
        except (OSError, SyntaxError):
            continue
        for node in tree.body:
            if not isinstance(node, ast.Assign):
                continue
            names = [t.id for t in node.targets if isinstance(t, ast.Name)]
            if "UNRESOLVED_METHODS" not in names:
                continue
            try:
                value = ast.literal_eval(node.value)
            except ValueError:
                return []
            return sorted(str(item) for item in value)
    return []



def _draft_unresolved(plugin_tree: Path, methods: list[str], spec, staging: Path):
    """Run the bounded draft loop, or return None when AI drafting is not configured.

    Not configuring it is the normal case and not an error: the build proceeds with anchored stubs
    and reports them honestly.
    """
    from kata_forge.ai_budget import AiBudget, AiDraftingDisabled, AiUsage, limits_from_env, write_ai_usage
    from kata_forge.draft_loop import run_draft_loop

    try:
        limits = limits_from_env()
    except AiDraftingDisabled:
        return None
    drafter = _load_drafter()
    if drafter is None:
        return None

    usage = AiUsage(build_id=staging.name, provider=os.environ.get("KATA_FORGE_LLM", "unknown"),
                    model=os.environ.get("KATA_FORGE_AI_MODEL", "unknown"), limits=limits)
    outcome = run_draft_loop(plugin_tree, methods=list(methods), pack=spec.pack,
                             budget=AiBudget(limits, usage), drafter=drafter)
    # Provenance is written even when nothing was drafted: "we tried and it cost this" is exactly
    # what a reviewer needs to see.
    write_ai_usage(staging / "ai-usage.json", usage)
    return outcome


def _load_drafter():
    """The configured drafter, or None. The forge ships no provider client by design -- a deployment
    supplies one, and until it does, drafting is off."""
    target = (os.environ.get("KATA_FORGE_DRAFTER") or "").strip()
    if not target or ":" not in target:
        return None
    module_name, _, attribute = target.partition(":")
    import importlib

    try:
        return getattr(importlib.import_module(module_name), attribute)
    except (ImportError, AttributeError):
        return None


# ---- wheel -------------------------------------------------------------------------------------
def build_wheel_in_compartment(plugin_dir: Path, out_dir: Path, workspace_root: Path) -> Path:
    """Build the plugin wheel INSIDE the Verify compartment.

    Building a wheel executes the package's build backend. That is untrusted code from a drafted
    plugin, so it runs unprivileged, with no network and no credentials — never on the build host
    directly. If the host cannot isolate, the build REFUSES rather than building it unconfined.
    """
    tools = Path(BUILD_TOOLS_ENV)
    tools_python = tools / "bin" / "python"
    if not tools_python.is_file():
        raise BuildRefused(
            f"no build-tools environment at {tools} (set KATA_FORGE_BUILD_TOOLS). The Verify "
            f"compartment has no network by design, so the build backend must be provided as a "
            f"read-only fixture; refusing rather than building unconfined.")
    workspace = fresh_workspace(workspace_root, "wheel")
    shutil.copytree(plugin_dir, workspace / "plugin", dirs_exist_ok=True)
    try:
        run = run_in_compartment(
            VERIFY,
            # The SANDBOX's python, not sys.executable: the caller's venv is deliberately not
            # bound into the compartment, so its interpreter does not exist inside.
            [str(tools_python), "-m", "pip", "wheel", "--no-deps", "--no-build-isolation",
             "-w", str(workspace / "dist"), str(workspace / "plugin")],
            workspace=workspace,
            ro_extra=(str(tools),),
        )
    except CompartmentUnavailable as exc:
        raise BuildRefused(
            f"cannot build the plugin wheel in an isolated compartment ({exc}); refusing rather "
            f"than running an untrusted build backend on the build host") from exc
    wheels = sorted((workspace / "dist").glob("*.whl")) if (workspace / "dist").is_dir() else []
    if run.returncode != 0 or not wheels:
        raise BuildRefused(
            f"plugin wheel build failed: {(run.stderr or run.stdout).strip()[:400]}")
    out_dir.mkdir(parents=True, exist_ok=True)
    target = out_dir / wheels[0].name
    shutil.copy2(wheels[0], target)
    return target


# ---- the chain ---------------------------------------------------------------------------------
@dataclass
class BuildResult:
    build_id: str
    bundle_dir: Path
    state: str
    mode: str
    reason: str = ""
    reused: bool = False
    artifacts: list[str] = field(default_factory=list)
    unresolved_methods: list[str] = field(default_factory=list)

    @property
    def installable(self) -> bool:
        """Only a bundle that reached ``verified`` with NO unwritten method may be staged. An
        UNRESOLVED build is a legitimate, reviewable output -- it is just never a deployment."""
        return self.state == "verified" and not self.unresolved_methods


def _phase_dir(output_root: Path, build_id: str) -> Path:
    return output_root / build_id


def _staging_dir(output_root: Path, build_id: str) -> Path:
    # Same filesystem as the final directory, so the promotion is a rename and not a copy.
    return output_root / f".staging-{build_id[:16]}"


def _tree_manifest(root: Path, exclude: set[str]) -> dict[str, str]:
    """{relpath: sha256} for every regular file under ``root`` except ``exclude``.

    Mirrors ``release_bundle.compute_tree_manifest`` in kata-subnets-deploy. The two repos have no
    dependency on each other, so this is a deliberate second implementation of one wire format — and
    the round-trip test (a forge bundle verified and installed by the REAL installer) is what stops
    them drifting.
    """
    manifest: dict[str, str] = {}
    for path in sorted(root.rglob("*")):
        if path.is_symlink():
            raise BuildError(f"symlink in bundle (refused): {path}")
        if not path.is_file():
            continue
        rel = str(path.relative_to(root)).replace(os.sep, "/")
        if rel in exclude:
            continue
        digest = hashlib.sha256()
        with open(path, "rb") as handle:
            for chunk in iter(lambda: handle.read(1 << 16), b""):
                digest.update(chunk)
        manifest[rel] = digest.hexdigest()
    return manifest


def _write_release_manifest(root: Path, *, abi: dict, plugin: dict, registry_change: dict,
                            unit_params: dict, extra: dict) -> dict:
    """Assemble the S4 release manifest: canonical bytes, complete tree, self-consistent digest."""
    tree = _tree_manifest(root, exclude={MANIFEST_FILENAME})
    manifest = {
        "schema_version": 1,
        "abi": abi,
        "plugin": plugin,
        "registry_change": registry_change,
        "unit_params": unit_params,
        "tree_manifest": tree,
        **extra,
    }
    payload = {k: v for k, v in manifest.items() if k != "bundle_digest"}
    digest = hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        + json.dumps(tree, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    ).hexdigest()
    manifest["bundle_digest"] = digest
    _fsync_write(root / MANIFEST_FILENAME, _canonical_json(manifest))
    return manifest


def build(
    *,
    output_root: str | Path,
    spec,
    kata_rev: str,
    kata_bot_rev: str,
    kata_forge_rev: str,
    kata_tree_hash: str,
    plugin_contract_version: int = 1,
    repo: str | None = None,
    subnet: int | None = None,
    catalog_path: str | Path | None = None,
    commit: str | None = None,
    new_attempt: bool = False,
    allow_gpu: bool = False,
    git_runner=None,
    wheel_builder=None,
    vendor_closure_files: int | None = None,
    vendor_entangled: list[str] | None = None,
    parity: dict | None = None,
    plugin_source: str | Path | None = None,
) -> BuildResult:
    """Run the whole chain and emit one immutable bundle. Never writes live state.

    Returns a ``BuildResult`` for every outcome, including REFUSE: a refusal with evidence is the
    deliverable when a subnet cannot be onboarded.
    """
    # 0 PREFLIGHT -- the cheapest refusals first, before anything is fetched or written.
    root = validate_output_root(output_root)

    # 1 RESOLVE + 2 FETCH. The commit is part of the build identity, so it must be known before the
    # build id exists; a retry therefore re-resolves but does not re-emit.
    canonical: CanonicalRepo = resolve_trusted_input(repo=repo, subnet=subnet,
                                                     catalog_path=catalog_path)
    fetch_root = root / ".sources"
    fetch_root.mkdir(parents=True, exist_ok=True)
    source_dir = fetch_root / f"{canonical.owner}__{canonical.repo}"
    shutil.rmtree(source_dir, ignore_errors=True)
    pinned = fetch_pinned(canonical, source_dir, commit=commit, git_runner=git_runner)

    inputs = BuildInputs(
        source_url=pinned.url,
        source_commit=pinned.commit,
        kata_rev=kata_rev,
        kata_bot_rev=kata_bot_rev,
        kata_forge_rev=kata_forge_rev,
        attempt_nonce=os.urandom(8).hex() if new_attempt else "1",
    )
    build_id = inputs.build_id()
    final = _phase_dir(root, build_id)

    # IDEMPOTENCE: an identical input resolves to an identical id. Re-emitting would spend again and
    # could produce a different bundle from the one already reviewed, so the prior result is returned.
    if final.is_dir():
        prior = read_build_state(final) or {}
        return BuildResult(build_id=build_id, bundle_dir=final,
                           state=str(prior.get("state") or "failed"),
                           mode=str(prior.get("mode") or ""),
                           reason="existing build for identical inputs; use --new-attempt to rebuild",
                           reused=True)

    staging = _staging_dir(root, build_id)
    shutil.rmtree(staging, ignore_errors=True)
    staging.mkdir(parents=True)
    state = BuildState(build_id=build_id, plugin_contract_version=plugin_contract_version,
                       evaluator_id=spec.evaluator_id, kata_tree_hash=kata_tree_hash)
    write_build_state(staging, state)

    def _refuse(reason: str, phase: str) -> BuildResult:
        state.state, state.phase, state.reason = "refused", phase, reason
        write_build_state(staging, state)
        # A refused build is retained for review but is NOT installable: it never gets a manifest,
        # so the S4 installer has nothing to verify and cannot promote it.
        os.replace(staging, final)
        return BuildResult(build_id=build_id, bundle_dir=final, state="refused", mode=REFUSE,
                           reason=reason)

    def _fail(exc: BaseException) -> None:
        """Record an UNEXPECTED failure durably before re-raising.

        Distinct from ``_refuse``: a refusal is a policy answer, a failure is the build breaking. The
        record stays in staging (never promoted to the build id) so a post-mortem can see how far it
        got, while remaining un-stageable by construction.
        """
        state.state, state.reason = "failed", f"{type(exc).__name__}: {exc}"[:500]
        try:
            write_build_state(staging, state)
        except OSError:
            pass  # the original exception is the one that matters

    try:
        return _run_phases(staging, final, state, spec, pinned, inputs, build_id,
                          _refuse, wheel_builder, allow_gpu, vendor_closure_files,
                          vendor_entangled, parity, kata_rev, kata_forge_rev,
                          kata_tree_hash, plugin_contract_version, plugin_source)
    except (BuildError, TrustedInputError):
        raise
    except BaseException as exc:
        _fail(exc)
        raise


def _run_phases(staging, final, state, spec, pinned, inputs, build_id, _refuse, wheel_builder,
                allow_gpu, vendor_closure_files, vendor_entangled, parity, kata_rev,
                kata_forge_rev, kata_tree_hash, plugin_contract_version,
                plugin_source=None) -> BuildResult:
    # 3 RESEARCH -- the credential scan first, so a leak stops the build before any AI input.
    state.phase = "research"
    write_build_state(staging, state)
    embedded = [f.as_evidence() for f in scan_embedded_secrets(pinned.path)]
    deps = classify_repo(pinned.path)
    cost = estimate_cost(pinned.path, deps=deps)
    licence = detect_license(pinned.path)

    # 4 FREE GATE + 5 DECIDE
    decision = decide(DecisionInputs(
        source_url=pinned.url, source_commit=pinned.commit, dep_verdict=deps.verdict,
        cost_class=cost.cost_class, needs_gpu=cost.needs_gpu, embedded_secrets=embedded,
        license=licence.as_evidence(), vendor_closure_files=vendor_closure_files,
        vendor_entangled=list(vendor_entangled or []), parity=dict(parity or {}),
        allow_gpu=allow_gpu,
    ))
    write_decision_record(staging / INTEGRATION_DECISION_FILENAME, decision)
    if decision.mode == REFUSE:
        return _refuse("; ".join(decision.reasons), "decide")

    # 6 SCAFFOLD -- the plugin, written only inside staging.
    state.state, state.phase = "drafting", "scaffold"
    write_build_state(staging, state)
    plugin_parent = staging / "plugin"
    plugin_parent.mkdir(parents=True, exist_ok=True)
    plugin_tree = plugin_parent / spec.repo_name
    if plugin_source is None:
        # No completed plugin supplied: scaffold one. Its subnet-specific methods are declared
        # UNRESOLVED, so the bundle is reviewable but the installer will refuse it.
        from kata_forge.generator import generate

        generate(spec, plugin_parent)
    else:
        # A COMPLETED plugin -- the realistic path, and how kata-sn126 and kata-sn60 exist today: a
        # human writes the subnet-specific methods, and the build packages, pins and verifies them.
        source_tree = Path(plugin_source).expanduser().resolve()
        if not source_tree.is_dir():
            raise BuildError(f"--plugin-src is not a directory: {source_tree}")
        shutil.copytree(source_tree, plugin_tree, symlinks=False,
                        ignore=shutil.ignore_patterns(".git", "__pycache__", "*.pyc", ".venv",
                                                      ".pytest_cache", ".ruff_cache", "dist"))
    state.unresolved_methods = read_unresolved_methods(plugin_tree)
    write_build_state(staging, state)

    # 8 DRAFT (plan 6). Bounded, verified, and OFF unless every AI budget bound is configured. With
    # no drafter every method simply stays UNRESOLVED -- which is why a scaffolded build is emitted
    # for review but refused by the installer.
    if state.unresolved_methods:
        state.state, state.phase = "drafting", "draft"
        write_build_state(staging, state)
        draft = _draft_unresolved(plugin_tree, state.unresolved_methods, spec, staging)
        if draft is not None:
            state.unresolved_methods = draft.unresolved
            _fsync_write(staging / "ai-draft.json",
                         _canonical_json(draft.as_evidence()))
            write_build_state(staging, state)

    # 7-8 INTEGRATE + verify. The wheel is built in the Verify compartment: a build backend is
    # untrusted code and must not run on the build host.
    state.state, state.phase = "verifying", "wheel"
    write_build_state(staging, state)
    builder = wheel_builder or (
        lambda plugin_dir, dist_dir: build_wheel_in_compartment(plugin_dir, dist_dir, staging / ".work"))
    try:
        wheel = builder(plugin_tree, staging / "dist")
    except BuildRefused as exc:
        return _refuse(str(exc), "wheel")

    # 9 EMIT
    state.phase = "emit"
    write_build_state(staging, state)
    _fsync_write(staging / SBOM_FILENAME,
                 _canonical_json(build_sbom(pinned.path, pinned.url, pinned.commit)))

    state.state, state.phase, state.conformance = "verified", "emit", "passed"
    write_build_state(staging, state)

    lane = {"subnet_id": spec.subnet_number, "lane_id": spec.pack, "pack": spec.pack,
            "mode": spec.mode, "evaluator": spec.evaluator_id,
            "source_repo": "", "upstream_repo": pinned.url, "upstream_commit": pinned.commit,
            "integration_mode": decision.mode.lower()}
    manifest = _write_release_manifest(
        staging,
        abi={"plugin_contract_version": plugin_contract_version, "kata_tree_hash": kata_tree_hash,
             "kata_rev": kata_rev, "plugin_rev": kata_forge_rev},
        plugin={"subnet_id": spec.subnet_number,
                "tree_root": f"plugin/{spec.repo_name}",
                "evaluator_id": spec.evaluator_id,
                "dist_name": spec.repo_name,
                "wheel": f"dist/{wheel.name}"},
        registry_change={"lane": lane, "lane_env": {}},
        unit_params={"timeout_start_sec": 5400, "round_gap_sec": 180, "requires_docker": True},
        extra={"build_inputs": inputs.canonical(), "sbom": SBOM_FILENAME,
               "decision": INTEGRATION_DECISION_FILENAME},
    )

    # ATOMIC PROMOTION: everything above happened in staging. Until this rename, no complete bundle
    # exists at the build id, so a crash can never leave a half-written bundle that looks finished.
    os.replace(staging, final)
    return BuildResult(build_id=build_id, bundle_dir=final, state="verified", mode=decision.mode,
                       artifacts=sorted(manifest["tree_manifest"]),
                       unresolved_methods=list(state.unresolved_methods or []),
                       reason=("methods still UNRESOLVED: "
                               + ", ".join(state.unresolved_methods or [])
                               if state.unresolved_methods else ""))
