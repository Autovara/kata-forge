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
import re
import shutil
import stat
import tempfile
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath

from kata_forge.compartment import (
    VERIFY,
    CompartmentUnavailable,
    fresh_workspace,
    run_in_compartment,
)
from kata_forge.cost import estimate_cost
from kata_forge.decision import CLONE, REFUSE, VENDOR, DecisionInputs, decide, write_decision_record
from kata_forge.deps import classify_repo
from kata_forge.license_gate import detect_license
from kata_forge.onboard import INTEGRATION_DECISION_FILENAME
from kata_forge.pinned_fetch import compartment_git_runner, fetch_pinned
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
_SOURCE_REPO_RE = re.compile(
    r"^[A-Za-z0-9][A-Za-z0-9._-]*/[A-Za-z0-9][A-Za-z0-9._-]*$"
)


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
    subnet_id: int = 0
    pack: str = ""
    evaluator: str = ""
    mode: str = ""
    source_repo: str = ""
    kata_tree_hash: str = ""
    plugin_contract_version: int = 0
    plugin_source_sha256: str = ""
    decision_inputs_sha256: str = ""
    build_tools_sha256: str = ""
    ai_config_sha256: str = ""
    policy_version: str = POLICY_VERSION
    attempt_nonce: str = "1"

    def canonical(self) -> dict:
        return {
            "source_url": self.source_url,
            "source_commit": self.source_commit,
            "kata_rev": self.kata_rev,
            "kata_bot_rev": self.kata_bot_rev,
            "kata_forge_rev": self.kata_forge_rev,
            "subnet_id": self.subnet_id,
            "pack": self.pack,
            "evaluator": self.evaluator,
            "mode": self.mode,
            "source_repo": self.source_repo,
            "kata_tree_hash": self.kata_tree_hash,
            "plugin_contract_version": self.plugin_contract_version,
            "plugin_source_sha256": self.plugin_source_sha256,
            "decision_inputs_sha256": self.decision_inputs_sha256,
            "build_tools_sha256": self.build_tools_sha256,
            "ai_config_sha256": self.ai_config_sha256,
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
    integration_mode: str = ""
    forge_verification: str = "not-run"
    conformance: str = "pending-installer"
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
            "integration_mode": self.integration_mode,
            "forge_verification": self.forge_verification,
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


_SOURCE_EXCLUDES = frozenset({
    ".git",
    ".venv",
    "__pycache__",
    ".pytest_cache",
    ".ruff_cache",
    "dist",
})


def _source_tree_digest(root: str | Path | None, *, allow_symlinks: bool = False) -> str:
    """Content identity for a caller-supplied plugin/tool tree.

    A path string is not an input identity: the bytes at that path can change between retries. The
    digest covers relative path, mode and content, rejects symlinks/special files, and ignores only
    reproducible build/cache debris. It is used in ``BuildInputs`` so editing a completed plugin or
    the offline build toolchain can never silently reuse an older bundle.
    """
    if root is None:
        return "generated"
    base = Path(root).expanduser().resolve()
    if not base.is_dir():
        raise BuildError(f"input tree is not a directory: {base}")
    digest = hashlib.sha256()
    for path in sorted(base.rglob("*")):
        rel_path = path.relative_to(base)
        if any(part in _SOURCE_EXCLUDES for part in rel_path.parts):
            continue
        if path.is_symlink():
            if not allow_symlinks:
                raise BuildError(f"symlink in input tree (refused): {path}")
            rel = str(rel_path).replace(os.sep, "/")
            digest.update(rel.encode("utf-8"))
            digest.update(b"\0link\0")
            digest.update(os.readlink(path).encode("utf-8"))
            digest.update(b"\n")
            continue
        if path.is_dir():
            continue
        if not path.is_file():
            raise BuildError(f"special file in input tree (refused): {path}")
        rel = str(rel_path).replace(os.sep, "/")
        digest.update(rel.encode("utf-8"))
        digest.update(b"\0")
        digest.update(f"{path.stat().st_mode & 0o777:o}".encode("ascii"))
        digest.update(b"\0")
        with open(path, "rb") as handle:
            for chunk in iter(lambda: handle.read(1 << 16), b""):
                digest.update(chunk)
        digest.update(b"\n")
    return digest.hexdigest()


def _canonical_digest(document: object) -> str:
    body = json.dumps(document, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(body.encode("utf-8")).hexdigest()


def _safe_source_relpath(value: str) -> str:
    rel = PurePosixPath(str(value))
    if rel.is_absolute() or not rel.parts or any(part in ("", ".", "..") for part in rel.parts):
        raise BuildError(f"unsafe source-relative path: {value!r}")
    return rel.as_posix()


def _regular_source_file(source_root: Path, rel: str) -> Path:
    safe = _safe_source_relpath(rel)
    candidate = source_root.joinpath(*PurePosixPath(safe).parts)
    if candidate.is_symlink() or not candidate.is_file():
        raise BuildError(f"vendored source is missing, a symlink, or not regular: {safe}")
    resolved = candidate.resolve()
    if source_root.resolve() not in resolved.parents:
        raise BuildError(f"vendored source escapes the pinned tree: {safe}")
    return candidate


def _resolve_vendor_files(
    source_root: Path,
    requested: list[str] | None,
) -> list[str]:
    """Return the exact closure that will be copied for a VENDOR decision.

    A closure is evidence only when the operator names every file. Inferring it from ``*.py`` is not
    conservative: a tiny scorer may still require JSON, templates, native data, or another non-Python
    artifact. A numeric count or an inferred language subset cannot identify the bytes.
    """
    if requested:
        files = sorted({_safe_source_relpath(item) for item in requested})
    else:
        files = []
    for rel in files:
        _regular_source_file(source_root, rel)
    return files


def _copy_vendor_closure(
    source_root: Path,
    plugin_tree: Path,
    package: str,
    files: list[str],
    *,
    source_url: str,
    source_commit: str,
) -> str:
    if not files:
        raise BuildError(
            "VENDOR selected without exact source files; pass --vendor-file for every closure file"
        )
    vendor_root = plugin_tree / package / "vendor_upstream"
    records = []
    for rel in files:
        source = _regular_source_file(source_root, rel)
        target = vendor_root.joinpath(*PurePosixPath(rel).parts)
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, target)
        records.append({
            "source": rel,
            "packaged": str(target.relative_to(plugin_tree)).replace(os.sep, "/"),
            "sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
        })
    pin = vendor_root / "PINNED.json"
    pin.write_text(
        _canonical_json({
            "schema_version": 1,
            "source_url": source_url,
            "source_commit": source_commit,
            "files": records,
        }),
        encoding="utf-8",
    )
    return str(pin.relative_to(plugin_tree)).replace(os.sep, "/")


def _copy_clone_snapshot(source_root: Path, staging: Path, repo_name: str) -> str:
    """Copy a pinned worktree into the bundle, rejecting symlinks and special files."""
    root = staging / "upstream" / repo_name
    for source in sorted(source_root.rglob("*")):
        rel = source.relative_to(source_root)
        if rel.parts and rel.parts[0] == ".git":
            continue
        if source.is_symlink():
            raise BuildError(f"symlink in CLONE snapshot (refused): {rel}")
        target = root / rel
        if source.is_dir():
            target.mkdir(parents=True, exist_ok=True)
        elif source.is_file():
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, target)
        else:
            raise BuildError(f"special file in CLONE snapshot (refused): {rel}")
    if not root.is_dir() or not any(path.is_file() for path in root.rglob("*")):
        raise BuildError("CLONE snapshot is empty")
    return str(root.relative_to(staging)).replace(os.sep, "/")


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



def _draft_unresolved(
    plugin_tree: Path,
    methods: list[str],
    spec,
    staging: Path,
    build_id: str,
    *,
    drafter=None,
    verifier=None,
):
    """Run the bounded draft loop, or return None when AI drafting is not configured.

    Not configuring it is the normal case and not an error: the build proceeds with anchored stubs
    and reports them honestly.
    """
    from kata_forge.ai_budget import (
        AiBudget,
        AiDraftingDisabled,
        AiUsage,
        limits_from_env,
        write_ai_usage,
    )
    from kata_forge.draft_loop import run_draft_loop

    try:
        limits = limits_from_env()
    except AiDraftingDisabled:
        return None
    drafter = drafter or _load_drafter()
    if drafter is None:
        return None
    if verifier is None:
        # Syntax parsing is useful feedback, but it is not evidence that score/run_candidate or
        # benchmark semantics work. Do not spend a model call when no authoritative subnet fixture
        # can decide whether to accept its output.
        return None

    usage = AiUsage(build_id=build_id, provider=os.environ.get("KATA_FORGE_LLM", "unknown"),
                    model=os.environ.get("KATA_FORGE_AI_MODEL", "unknown"), limits=limits)
    outcome = run_draft_loop(plugin_tree, methods=list(methods), pack=spec.pack,
                             budget=AiBudget(limits, usage), drafter=drafter, verify=verifier)
    # Provenance is written even when nothing was drafted: "we tried and it cost this" is exactly
    # what a reviewer needs to see.
    write_ai_usage(staging / "ai-usage.json", usage)
    return outcome


def _load_drafter():
    """Return the configured compartment command drafter, or ``None``.

    The old seam imported ``module:function`` and called it in the forge process. That meant the
    model/provider client inherited the operator's filesystem, environment and network even though
    the parse check ran in a namespace. The production seam is now an argv JSON array. The command
    runs inside DRAFT (no network, clean environment, no home) and receives two final arguments:
    ``request.json`` and ``response.py``.

    A Python callable may still be injected directly into :func:`build` by unit tests; the CLI never
    exposes that seam.
    """
    raw = (os.environ.get("KATA_FORGE_DRAFTER_ARGV_JSON") or "").strip()
    if not raw:
        return None
    try:
        argv = json.loads(raw)
    except ValueError as exc:
        raise BuildError(f"KATA_FORGE_DRAFTER_ARGV_JSON is invalid JSON: {exc}") from exc
    if (
        not isinstance(argv, list)
        or not argv
        or any(not isinstance(item, str) or not item for item in argv)
    ):
        raise BuildError("KATA_FORGE_DRAFTER_ARGV_JSON must be a non-empty JSON string array")
    declared_executable = Path(argv[0])
    if not declared_executable.is_absolute():
        raise BuildError("the Draft command must be an absolute executable under /usr or /bin")
    try:
        executable = declared_executable.resolve(strict=True)
    except OSError as exc:
        raise BuildError(f"the Draft command does not resolve to an executable: {exc}") from exc
    usr = Path("/usr").resolve()
    bin_dir = Path("/bin").resolve()
    if (
        not executable.is_file()
        or not os.access(executable, os.X_OK)
        or not any(executable == root or root in executable.parents for root in (usr, bin_dir))
    ):
        raise BuildError("the Draft command must resolve to an executable under /usr or /bin")
    # Run the canonical target. A spelling such as /usr/../tmp/tool must never pass the prefix check
    # and then execute from the writable workspace inside the namespace.
    argv[0] = str(executable)

    from kata_forge.compartment import DRAFT

    def _draft(method: str, prompt: str) -> str:
        scratch = _compartment_scratch()
        workspace = fresh_workspace(scratch, "draft")
        request = workspace / "request.json"
        response = workspace / "response.py"
        request.write_text(
            json.dumps({"schema_version": 1, "method": method, "prompt": prompt}),
            encoding="utf-8",
        )
        try:
            run = run_in_compartment(
                DRAFT,
                [*argv, str(request), str(response)],
                workspace=workspace,
            )
        except CompartmentUnavailable as exc:
            raise BuildError(f"Draft compartment unavailable: {exc}") from exc
        if run.returncode != 0:
            raise BuildError(
                f"Draft command failed for {method}: {(run.stderr or run.stdout).strip()[:800]}"
            )
        try:
            body = response.read_text(encoding="utf-8")
        except OSError as exc:
            raise BuildError(f"Draft command produced no response for {method}: {exc}") from exc
        if not body.strip():
            raise BuildError(f"Draft command produced an empty response for {method}")
        return body

    return _draft



def _compartment_scratch() -> Path:
    """A scratch root for compartment workspaces, deliberately OUTSIDE the build output root.

    ``fresh_workspace`` makes every ancestor searchable so bwrap (which resolves bind sources after
    dropping privileges) can reach it. Pointing that at the output root would relax its 0700 mode --
    the very property ``validate_output_root`` enforces to stop the staging tree being swapped -- so
    the two must not share a path.
    """
    scratch = Path(tempfile.mkdtemp(prefix="kata-forge-compartment-"))
    scratch.chmod(0o755)
    return scratch


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



def _run_plugin_smoke_check(plugin_tree: Path, workspace_root: Path) -> str:
    """Check, in the Verify compartment, what the forge can HONESTLY establish about the plugin.

    Scope is deliberately narrow. The compartment has no network and no Kata core, so the plugin
    cannot be imported here — resolving its singleton needs the candidate runtime, which only the
    trusted installer builds. What the forge can prove is that the plugin declares a ``kata.subnets``
    entry point, that the module it names actually exists in the tree, and that every module parses.
    A plugin failing any of those is definitely broken; passing them is not a claim that it works.

    Returns ``"passed"``, ``"failed"``, or ``"not-run"`` when the host cannot isolate. ``not-run`` is
    never reported as a pass: an unrun check that claims success is the dishonesty this exists to
    prevent, and the installer re-verifies from scratch either way.
    """
    if os.environ.get("KATA_FORGE_SKIP_SMOKE") == "1":
        return "not-run"
    script = (
        "import pathlib, tomllib, sys\n"
        "root = pathlib.Path('plugin')\n"
        "cfg = tomllib.loads((root / 'pyproject.toml').read_text())\n"
        "eps = cfg.get('project', {}).get('entry-points', {}).get('kata.subnets')\n"
        "assert eps, 'no kata.subnets entry point declared; the plugin is undiscoverable'\n"
        "value = next(iter(eps.values()))\n"
        "module, _, attr = value.partition(':')\n"
        "assert attr, f'entry point {value!r} must be module:attribute'\n"
        "target = root.joinpath(*module.split('.'))\n"
        "assert target.with_suffix('.py').exists() or (target / '__init__.py').exists(), \\\n"
        "    f'entry point module {module!r} is not in the plugin tree'\n"
        "for py in sorted(root.rglob('*.py')):\n"
        "    compile(py.read_text(), str(py), 'exec')\n"
        "print('smoke-ok')\n"
    )
    try:
        workspace = fresh_workspace(workspace_root, "smoke")
        shutil.copytree(plugin_tree, workspace / "plugin", dirs_exist_ok=True)
        run = run_in_compartment(VERIFY, [COMPARTMENT_PYTHON, "-c", script], workspace=workspace)
    except (CompartmentUnavailable, OSError):
        return "not-run"
    return "passed" if run.returncode == 0 and "smoke-ok" in run.stdout else "failed"


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
    forge_verification: str = "not-run"
    conformance: str = "pending-installer"

    @property
    def installable(self) -> bool:
        """Only a bundle that reached forge verification with NO unwritten method may enter the
        trusted installer. Authoritative candidate-runtime conformance remains an installer gate.
        An UNRESOLVED build is a legitimate, reviewable output -- it is never deployable."""
        return (
            self.state == "verified"
            and not self.unresolved_methods
            and self.forge_verification == "passed"
            and self.conformance == "pending-installer"
        )


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


def _verify_existing_build(root: Path, expected_build_id: str) -> dict:
    """Recompute an immutable prior result before treating it as an idempotent hit."""
    state = read_build_state(root)
    if not isinstance(state, dict):
        raise BuildError(f"existing build {root} has no valid {BUILD_STATE_FILENAME}")
    if state.get("build_id") != expected_build_id:
        raise BuildError(
            f"existing build id mismatch: directory {expected_build_id}, "
            f"state {state.get('build_id')!r}"
        )
    if state.get("state") != "verified":
        # A refusal intentionally has no release manifest/tree digest, so its evidence has no
        # immutable envelope we can recompute. Reusing it on the strength of build-state.json alone
        # would let accidental/tampered bytes masquerade as the prior policy result. Keep the record
        # for review, but require an explicit new attempt to execute the policy again.
        raise BuildError(
            f"existing build {root} is {state.get('state')!r} and has no verifiable release "
            "manifest; inspect it or use --new-attempt"
        )
    try:
        manifest = json.loads((root / MANIFEST_FILENAME).read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise BuildError(f"existing verified build has no valid manifest: {exc}") from exc
    declared_tree = manifest.get("tree_manifest")
    if not isinstance(declared_tree, dict):
        raise BuildError("existing verified build manifest has no tree_manifest")
    actual_tree = _tree_manifest(root, exclude={MANIFEST_FILENAME})
    if actual_tree != declared_tree:
        raise BuildError("existing build tree differs from its manifest; refusing reuse")
    payload = {key: value for key, value in manifest.items() if key != "bundle_digest"}
    digest = hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        + json.dumps(actual_tree, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode(
            "utf-8"
        )
    ).hexdigest()
    if manifest.get("bundle_digest") != digest:
        raise BuildError("existing build bundle digest is invalid; refusing reuse")
    return state


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
    vendor_files: list[str] | None = None,
    parity: dict | None = None,
    plugin_source: str | Path | None = None,
    source_repo: str = "",
    drafter=None,
    draft_verifier=None,
) -> BuildResult:
    """Run the whole chain and emit one immutable bundle. Never writes live state.

    Returns a ``BuildResult`` for every outcome, including REFUSE: a refusal with evidence is the
    deliverable when a subnet cannot be onboarded.
    """
    # 0 PREFLIGHT -- the cheapest refusals first, before anything is fetched or written.
    root = validate_output_root(output_root)
    from kata_forge.spec import validate_spec

    # ``build`` is a public Python seam as well as a CLI handler. Do not trust a caller to have
    # obtained its dataclass through the validating constructor.
    spec = validate_spec(
        subnet_number=spec.subnet_number,
        pack=spec.pack,
        evaluator_id=spec.evaluator_id,
        mode=spec.mode,
        name=spec.name,
    )
    # source_repo is the Kata repo whose PRs route to this lane. kata-bot requires it, so a build
    # without one produces a registry the resident refuses to parse: catch it here, not at install.
    source_repo = str(source_repo or "").strip()
    if not source_repo:
        raise BuildError(
            "--source-repo is required: it is the Kata repo whose PRs route to this lane, and "
            "kata-bot refuses a registry lane without one")
    if not _SOURCE_REPO_RE.fullmatch(source_repo):
        raise BuildError("--source-repo must be an owner/repo slug")
    plugin_source_digest = _source_tree_digest(plugin_source)
    build_tools_digest = (
        "injected-wheel-builder"
        if wheel_builder is not None
        else _source_tree_digest(BUILD_TOOLS_ENV, allow_symlinks=True)
    )
    decision_inputs_digest = _canonical_digest({
        "allow_gpu": bool(allow_gpu),
        "vendor_closure_files": vendor_closure_files,
        "vendor_entangled": sorted(vendor_entangled or []),
        "vendor_files": sorted(vendor_files or []),
        "parity": parity or {},
    })
    ai_config_digest = _canonical_digest({
        "provider": os.environ.get("KATA_FORGE_LLM", ""),
        "model": os.environ.get("KATA_FORGE_AI_MODEL", ""),
        "max_attempts": os.environ.get("KATA_FORGE_AI_MAX_ATTEMPTS", ""),
        "max_wall_seconds": os.environ.get("KATA_FORGE_AI_MAX_WALL_SECONDS", ""),
        "max_input_bytes": os.environ.get("KATA_FORGE_AI_MAX_INPUT_BYTES", ""),
        "max_output_tokens": os.environ.get("KATA_FORGE_AI_MAX_OUTPUT_TOKENS", ""),
        "max_spend_usd": os.environ.get("KATA_FORGE_AI_MAX_SPEND_USD", ""),
        "provider_enforces_spend": os.environ.get(
            "KATA_FORGE_AI_PROVIDER_ENFORCES_SPEND", ""
        ),
        "drafter_argv": os.environ.get("KATA_FORGE_DRAFTER_ARGV_JSON", ""),
        "drafter_injected_for_test": drafter is not None,
        "authoritative_verifier_injected_for_test": draft_verifier is not None,
    })

    # 1 RESOLVE + 2 FETCH. The commit is part of the build identity, so it must be known before the
    # build id exists; a retry therefore re-resolves but does not re-emit.
    canonical: CanonicalRepo = resolve_trusted_input(repo=repo, subnet=subnet,
                                                     catalog_path=catalog_path)
    # FETCH runs in the Fetch compartment: the one compartment with egress, and the one that must
    # never see a credential, the operator's home, or host git config. A caller-supplied runner
    # (tests) wins, so this adds isolation without taking away injectability.
    # The clone target must be WRITABLE BY THE SANDBOX UID: inside the compartment the workload is
    # uid 65534 and the workspace is its only writable surface, so `fresh_workspace` (which sets the
    # mode and makes the ancestors searchable) is required here -- a plain mkdtemp is not enough.
    fetch_scratch = fresh_workspace(_compartment_scratch(), "fetch")
    fetch_root = fetch_scratch / "sources"
    fetch_root.mkdir(parents=True, exist_ok=True)
    fetch_root.chmod(0o777)
    source_dir = fetch_root / f"{canonical.owner}__{canonical.repo}"
    shutil.rmtree(source_dir, ignore_errors=True)
    runner = git_runner or compartment_git_runner(fetch_scratch)
    pinned = fetch_pinned(canonical, source_dir, commit=commit, git_runner=runner)

    inputs = BuildInputs(
        source_url=pinned.url,
        source_commit=pinned.commit,
        kata_rev=kata_rev,
        kata_bot_rev=kata_bot_rev,
        kata_forge_rev=kata_forge_rev,
        subnet_id=int(spec.subnet_number),
        pack=str(spec.pack),
        evaluator=str(spec.evaluator_id),
        mode=str(spec.mode),
        source_repo=source_repo,
        kata_tree_hash=kata_tree_hash,
        plugin_contract_version=int(plugin_contract_version),
        plugin_source_sha256=plugin_source_digest,
        decision_inputs_sha256=decision_inputs_digest,
        build_tools_sha256=build_tools_digest,
        ai_config_sha256=ai_config_digest,
        attempt_nonce=os.urandom(8).hex() if new_attempt else "1",
    )
    build_id = inputs.build_id()
    final = _phase_dir(root, build_id)

    # IDEMPOTENCE: an identical input resolves to an identical id. Re-emitting would spend again and
    # could produce a different bundle from the one already reviewed, so the prior result is returned.
    if final.is_dir():
        prior = _verify_existing_build(final, build_id)
        return BuildResult(
            build_id=build_id,
            bundle_dir=final,
            state=str(prior.get("state") or "failed"),
            mode=str(prior.get("integration_mode") or ""),
            reason="existing build for identical inputs; use --new-attempt to rebuild",
            reused=True,
            unresolved_methods=list(prior.get("unresolved_methods") or []),
            forge_verification=str(prior.get("forge_verification") or "not-run"),
            conformance=str(prior.get("conformance") or "pending-installer"),
        )

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
                           reason=reason,
                           unresolved_methods=list(state.unresolved_methods or []),
                           forge_verification=state.forge_verification,
                           conformance=state.conformance)

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
                          vendor_entangled, vendor_files, parity, kata_rev,
                          kata_tree_hash, plugin_contract_version, plugin_source,
                          source_repo, drafter, draft_verifier)
    except (BuildError, TrustedInputError):
        raise
    except BaseException as exc:
        _fail(exc)
        raise


def _run_phases(staging, final, state, spec, pinned, inputs, build_id, _refuse, wheel_builder,
                allow_gpu, vendor_closure_files, vendor_entangled, vendor_files, parity, kata_rev,
                kata_tree_hash, plugin_contract_version, plugin_source=None, source_repo="",
                drafter=None, draft_verifier=None) -> BuildResult:
    # 3 RESEARCH -- the credential scan first, so a leak stops the build before any AI input.
    state.phase = "research"
    write_build_state(staging, state)
    embedded = [f.as_evidence() for f in scan_embedded_secrets(pinned.path)]
    deps = classify_repo(pinned.path)
    cost = estimate_cost(pinned.path, deps=deps)
    licence = detect_license(pinned.path)
    exact_vendor_files = _resolve_vendor_files(
        pinned.path,
        vendor_files,
    )
    effective_vendor_count = (
        vendor_closure_files
        if vendor_closure_files is not None
        else (len(exact_vendor_files) if exact_vendor_files else None)
    )

    # 4 FREE GATE + 5 DECIDE
    decision = decide(DecisionInputs(
        source_url=pinned.url, source_commit=pinned.commit, dep_verdict=deps.verdict,
        cost_class=cost.cost_class, needs_gpu=cost.needs_gpu, embedded_secrets=embedded,
        license=licence.as_evidence(), vendor_closure_files=effective_vendor_count,
        vendor_files=exact_vendor_files,
        vendor_entangled=list(vendor_entangled or []), parity=dict(parity or {}),
        allow_gpu=allow_gpu,
    ))
    write_decision_record(staging / INTEGRATION_DECISION_FILENAME, decision)
    if decision.mode == REFUSE:
        return _refuse("; ".join(decision.reasons), "decide")
    state.integration_mode = decision.mode
    write_build_state(staging, state)

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
        draft = _draft_unresolved(
            plugin_tree,
            state.unresolved_methods,
            spec,
            staging,
            build_id,
            drafter=drafter,
            verifier=draft_verifier,
        )
        if draft is not None:
            state.unresolved_methods = draft.unresolved
            _fsync_write(staging / "ai-draft.json",
                         _canonical_json(draft.as_evidence()))
            write_build_state(staging, state)

    # 7 INTEGRATE. The selected policy outcome now changes actual bundle bytes, not only a label in
    # integration-decision.json. VENDOR copies the exact measured closure into the plugin package;
    # CLONE retains the complete pinned worktree (minus .git) for deterministic trusted promotion.
    if decision.mode == VENDOR:
        vendor_pin = _copy_vendor_closure(
            pinned.path,
            plugin_tree,
            spec.package,
            exact_vendor_files,
            source_url=pinned.url,
            source_commit=pinned.commit,
        )
        integration = {
            "mode": "vendor",
            "source_url": pinned.url,
            "source_commit": pinned.commit,
            "vendor_manifest": f"plugin/{spec.repo_name}/{vendor_pin}",
        }
    elif decision.mode == CLONE:
        clone_root = _copy_clone_snapshot(pinned.path, staging, pinned.path.name)
        integration = {
            "mode": "clone",
            "source_url": pinned.url,
            "source_commit": pinned.commit,
            "tree_root": clone_root,
            "install_path": f"/srv/kata-sn{spec.subnet_number}-upstream",
        }
    else:  # fixed policy currently has only these two non-refusal outcomes
        return _refuse(f"unsupported integration mode {decision.mode!r}", "integrate")

    # 8 verify. The wheel is built in the Verify compartment: a build backend is
    # untrusted code and must not run on the build host.
    state.state, state.phase = "verifying", "wheel"
    write_build_state(staging, state)
    builder = wheel_builder or (
        lambda plugin_dir, dist_dir: build_wheel_in_compartment(
            plugin_dir, dist_dir, _compartment_scratch()))
    try:
        wheel = builder(plugin_tree, staging / "dist")
    except BuildRefused as exc:
        return _refuse(str(exc), "wheel")

    # 9 EMIT
    state.phase = "emit"
    write_build_state(staging, state)
    _fsync_write(staging / SBOM_FILENAME,
                 _canonical_json(build_sbom(pinned.path, pinned.url, pinned.commit)))

    # FORGE VERIFICATION is narrower than authoritative runtime conformance: it proves the entry
    # point exists and every module parses inside VERIFY. The trusted installer builds the candidate
    # runtime and performs entry-point/ABI/decision/core conformance later. Keep the states distinct
    # so the bundle never claims that forge ran a test it could not run.
    state.forge_verification = _run_plugin_smoke_check(
        plugin_tree, _compartment_scratch()
    )
    if state.forge_verification != "passed":
        return _refuse(
            f"plugin verification was {state.forge_verification}; refusing an unverified bundle",
            "conformance",
        )
    state.conformance = "pending-installer"
    state.state, state.phase = "verified", "emit"
    write_build_state(staging, state)

    # The registry lane must satisfy kata-bot's OWN validator, not merely the installer's -- the
    # resident refuses to start on a registry it cannot parse, so an "installed" lane with a bad
    # entry here is a lane that never runs. Three rules the schema enforces and this must honour:
    #   * source_repo is the Kata repo whose PRs route to this lane, and must be non-empty;
    #   * entry_point declares how the plugin is discovered, and is required;
    #   * CLONE requires an upstream pin, VENDOR FORBIDS one (the vendored copy is the single
    #     source of truth, and a second pin would drift).
    lane = {
        "subnet_id": spec.subnet_number,
        "lane_id": spec.pack,
        "pack": spec.pack,
        "mode": spec.mode,
        "evaluator": spec.evaluator_id,
        "source_repo": source_repo,
        "plugin_path": f"/srv/{spec.repo_name}",
        "integration_mode": decision.mode.lower(),
        "challenge_config": {},
        "entry_point": {
            "distribution": spec.repo_name,
            "name": f"sn{spec.subnet_number}",
            "value": f"{spec.package}:{spec.singleton}",
        },
    }
    if decision.mode == CLONE:
        lane["upstream_repo"] = pinned.url
        lane["upstream_commit"] = pinned.commit
        lane["challenge_config"] = {
            "upstream_path": f"/srv/kata-sn{spec.subnet_number}-upstream"
        }
    manifest = _write_release_manifest(
        staging,
        abi={"plugin_contract_version": plugin_contract_version, "kata_tree_hash": kata_tree_hash,
             "kata_rev": kata_rev, "plugin_rev": _source_tree_digest(plugin_tree)},
        plugin={"subnet_id": spec.subnet_number,
                "tree_root": f"plugin/{spec.repo_name}",
                "evaluator_id": spec.evaluator_id,
                "dist_name": spec.repo_name,
                "wheel": f"dist/{wheel.name}"},
        registry_change={"lane": lane, "lane_env": {}},
        unit_params={"timeout_start_sec": 5400, "round_gap_sec": 180, "requires_docker": True},
        extra={"build_inputs": inputs.canonical(), "sbom": SBOM_FILENAME,
               "integration": integration,
               "decision": INTEGRATION_DECISION_FILENAME},
    )

    # ATOMIC PROMOTION: everything above happened in staging. Until this rename, no complete bundle
    # exists at the build id, so a crash can never leave a half-written bundle that looks finished.
    os.replace(staging, final)
    return BuildResult(build_id=build_id, bundle_dir=final, state="verified", mode=decision.mode,
                       artifacts=sorted(manifest["tree_manifest"]),
                       unresolved_methods=list(state.unresolved_methods or []),
                       forge_verification=state.forge_verification,
                       conformance=state.conformance,
                       reason=("methods still UNRESOLVED: "
                               + ", ".join(state.unresolved_methods or [])
                               if state.unresolved_methods else ""))
