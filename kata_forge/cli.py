"""The ``kata-forge`` command line: scaffold a subnet plugin and emit its lane config.

F1 wires the CLI and validates the spec; generation (``new`` -> files) lands in F2 and the
config artifact (``lane-config``) in F4. Both commands validate their spec up front so a bad
invocation fails before any side effect.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from kata_forge.spec import SpecError, spec_from_args


def _add_spec_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--subnet", type=int, required=True, help="Subnet number, e.g. 126.")
    parser.add_argument("--pack", required=True, help="Lane pack, e.g. sn126__poker44.")
    parser.add_argument("--evaluator", required=True, help="Evaluator id, e.g. sn126_poker44.")
    parser.add_argument("--mode", default="miner", help="Submission mode (default: miner).")
    parser.add_argument("--name", default="", help="Display slug (default: derived from --pack).")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="kata-forge", description="Scaffold Kata subnet plugins.")
    subcommands = parser.add_subparsers(dest="command", required=True)

    new = subcommands.add_parser("new", help="Scaffold a kata-sn<N> plugin skeleton.")
    _add_spec_arguments(new)
    new.add_argument("--out", default=".", help="Directory to create kata-sn<N>/ under.")
    new.add_argument("--force", action="store_true", help="Overwrite an existing target.")

    lane = subcommands.add_parser("lane-config", help="Emit the kata-bot lane config for a subnet.")
    _add_spec_arguments(lane)
    lane.add_argument("--release-path", default="", help="Host path to a pinned benchmark release.")
    lane.add_argument("--sample-size", type=int, default=0, help="Groups sampled per challenge.")
    lane.add_argument("--org", default="Autovara", help="GitHub org for source_repos.")
    lane.add_argument("--srv-root", default="/srv", help="Deploy root for the editable path.")
    lane.add_argument("--env", default="", help="An existing .env to emit a reviewable patch against.")
    lane.add_argument("--out", default="", help="Write the patch to this file instead of stdout.")
    lane.add_argument("--repo", default="", help="Validator repo to derive egress hosts + secrets from.")

    extract = subcommands.add_parser("extract", help="Analyze a validator repo and scaffold a plugin.")
    extract.add_argument("--repo", default="", help="Validator repo url or local path.")
    extract.add_argument("--subnet", type=int, default=0, help="Subnet number (needs a resolver).")
    extract.add_argument("--commit", default="", help="Pin the repo at this commit.")
    extract.add_argument("--work-dir", default="", help="Where to clone a remote repo.")
    extract.add_argument("--out", default="", help="Write the analysis report (+scaffold) here.")
    extract.add_argument("--pack", default="", help="Lane pack; enables the anchored scaffold.")
    extract.add_argument("--evaluator", default="", help="Evaluator id; enables the anchored scaffold.")
    extract.add_argument("--mode", default="miner", help="Submission mode for the scaffold.")
    extract.add_argument("--name", default="", help="Display slug for the scaffold.")
    extract.add_argument("--force", action="store_true", help="Overwrite an existing scaffold.")
    extract.add_argument("--llm", action="store_true", help="Opt-in: draft the stubs via KATA_FORGE_LLM.")

    # S5: the PRODUCTION input path. Deliberately separate from `extract`, which stays permissive
    # (local paths, unpinned) for offline research. This one refuses anything that is not a canonical
    # public GitHub repository, and stops at the decision rather than scaffolding.
    decide_cmd = subcommands.add_parser(
        "decide", help="Resolve a canonical validator repo and decide VENDOR/CLONE/REFUSE (S5).")
    decide_cmd.add_argument("--repo", default=None,
                            help="Canonical https://github.com/<owner>/<repo> URL.")
    decide_cmd.add_argument("--subnet", type=int, default=None,
                            help="Subnet number, resolved ONLY through --catalog.")
    decide_cmd.add_argument("--catalog", default=None,
                            help="Local versioned subnet-catalog.json (required with --subnet).")
    decide_cmd.add_argument("--commit", default=None, help="Pin at this full 40-character sha.")
    decide_cmd.add_argument("--work-dir", required=True, help="Where to clone the pinned source.")
    decide_cmd.add_argument("--out", required=True, help="Where to write integration-decision.json.")
    decide_cmd.add_argument("--allow-gpu", action="store_true",
                            help="Explicitly permit a GPU-requiring validator.")

    # S7: the one-command chain. Non-root, transactional, and it never writes live state.
    build_cmd = subcommands.add_parser(
        "build", help="Resolve, fetch, decide and emit one immutable release bundle (S7).")
    build_cmd.add_argument("--repo", default=None,
                           help="Canonical https://github.com/<owner>/<repo> URL.")
    build_cmd.add_argument("--subnet", type=int, default=None,
                           help="Subnet number, resolved ONLY through --catalog.")
    build_cmd.add_argument("--catalog", default=None, help="Local versioned subnet-catalog.json.")
    build_cmd.add_argument("--commit", default=None, help="Pin at this full 40-character sha.")
    build_cmd.add_argument("--out", default=None,
                           help=f"Output root (or ${build_output_root_env()}); absolute, mode 0700.")
    build_cmd.add_argument("--pack", default=None,
                           help="Lane pack (default: derived from --subnet and the repo name).")
    build_cmd.add_argument("--evaluator", default=None,
                           help="Evaluator id (default: derived from the pack).")
    build_cmd.add_argument("--mode", default="miner", help="Submission mode (default: miner).")
    build_cmd.add_argument("--name", default="", help="Display slug (default: derived from --pack).")
    # Revisions and the core hash are READ FROM THE CHECKOUTS by default. Requiring an operator
    # to paste four hashes correctly is how a bundle ends up pinned to the wrong core.
    build_cmd.add_argument("--kata-root", default=None,
                           help="Path to the kata checkout (default: sibling of this repo).")
    build_cmd.add_argument("--kata-bot-root", default=None,
                           help="Path to the kata-bot checkout (default: sibling).")
    build_cmd.add_argument("--kata-rev", default=None, help="Override the detected kata revision.")
    build_cmd.add_argument("--kata-bot-rev", default=None, help="Override the detected revision.")
    build_cmd.add_argument("--kata-forge-rev", default=None, help="Override the detected revision.")
    build_cmd.add_argument("--kata-tree-hash", default=None,
                           help="Override the computed kata core content hash.")
    build_cmd.add_argument("--new-attempt", action="store_true",
                           help="Change the attempt nonce, producing a different build id.")
    build_cmd.add_argument("--source-repo", default="Autovara/kata",
                           help="The Kata repo whose PRs route to this lane.")
    build_cmd.add_argument("--plugin-src", default=None,
                           help="A COMPLETED plugin tree to package instead of scaffolding one.")
    build_cmd.add_argument("--vendor-closure-files", type=int, default=None,
                           help="Measured scorer closure size (VENDOR evidence).")
    build_cmd.add_argument("--vendor-entangled", default="",
                           help="Comma-separated entanglements, e.g. docker,bittensor.")
    build_cmd.add_argument("--parity-json", default=None,
                           help="Path to an executed parity fixture result (CLONE evidence).")
    build_cmd.add_argument("--allow-gpu", action="store_true",
                           help="Explicitly permit a GPU-requiring validator.")

    survey = subcommands.add_parser("survey", help="Rank many local repos as onboarding candidates.")
    survey.add_argument("paths", nargs="+", help="Local repo paths to analyze and rank.")
    survey.add_argument("--out", default="", help="Write the ranked table to this file.")

    return parser


def _run_survey(args: argparse.Namespace) -> int:
    from kata_forge.batch import render_survey_table, survey

    rows = survey(list(args.paths))
    table = render_survey_table(rows)
    if args.out:
        Path(args.out).expanduser().write_text(table, encoding="utf-8")
        print(f"kata-forge: wrote survey of {len(rows)} repos to {args.out}")
    else:
        print(table, end="")
    return 0


def _run_extract(args: argparse.Namespace) -> int:
    from kata_forge.resolver import RepoResolveError, resolve_repo

    resolver = None
    if not args.repo and args.subnet:  # no repo given -> resolve the subnet from the chain
        from kata_forge.chain import chain_resolver

        resolver = chain_resolver()
    try:
        resolved = resolve_repo(
            repo=args.repo or None,
            subnet=args.subnet or None,
            commit=args.commit or None,
            work_dir=args.work_dir or None,
            resolver=resolver,
        )
    except RepoResolveError as error:
        print(f"kata-forge: error: {error}", file=sys.stderr)
        return 2
    from kata_forge.anchors import extract_anchors
    from kata_forge.deps import classify_repo

    print(f"kata-forge: resolved {resolved.source}")
    print(f"  path:   {resolved.path}")
    print(f"  commit: {resolved.commit or '(not a git repo)'}")
    print(f"  cloned: {resolved.was_cloned}")
    report = classify_repo(resolved.path)
    print(f"  deps:   {report.verdict}")
    for label, names in (
        ("paid-api", report.paid_api),
        ("gpu", report.gpu),
        ("gated-data", report.gated_data),
        ("unclassified", report.unclassified),
    ):
        if names:
            print(f"    {label}: {', '.join(names)}")
    anchors = extract_anchors(resolved.path)
    print("  anchors:")
    for kind in ("scorer", "benchmark", "miner"):
        anchor = getattr(anchors, kind)
        if anchor:
            print(f"    {kind}: {anchor.file}:{anchor.lineno} {anchor.symbol} [{anchor.confidence}]")
        else:
            print(f"    {kind}: (not found)")

    from kata_forge.cost import estimate_cost
    from kata_forge.secrets import extract_secrets

    secret_report = extract_secrets(resolved.path)
    if secret_report.required_secrets or secret_report.allowed_hosts:
        print("  egress:")
        if secret_report.required_secrets:
            print(f"    secrets: {', '.join(secret_report.required_secrets)}")
        if secret_report.allowed_hosts:
            print(f"    hosts: {', '.join(secret_report.allowed_hosts)}")
        paid = secret_report.paid_providers
        print(f"    paid providers: {', '.join(paid) if paid else 'none (free-tier only)'}")

    cost = estimate_cost(resolved.path, deps=report, secrets=secret_report)
    print(f"  cost:   {cost.summary}")
    for note in cost.notes:
        print(f"    note: {note}")

    if not args.out:
        print("  tip: pass --out DIR to write the analysis report (+ --pack/--evaluator for a scaffold)")
        return 0

    from kata_forge.report import write_extract
    from kata_forge.spec import SpecError, validate_spec

    spec = None
    if args.pack or args.evaluator:  # a scaffold was requested
        try:
            spec = validate_spec(
                subnet_number=args.subnet, pack=args.pack, evaluator_id=args.evaluator,
                mode=args.mode, name=args.name,
            )
        except SpecError as error:
            print(f"kata-forge: error: {error}", file=sys.stderr)
            return 2
    drafter = None
    if args.llm:  # opt-in draft seam; a missing/unwired provider degrades to a note, never fatal
        from kata_forge.llm import LlmUnavailable, default_drafter

        try:
            drafter = default_drafter()
        except LlmUnavailable as error:
            print(f"  llm: {error} (scaffolding without drafts)")
    outputs = write_extract(
        out_dir=args.out, subnet=args.subnet or None, resolved=resolved,
        deps=report, anchors=anchors, cost=cost, spec=spec, drafter=drafter, force=args.force,
    )
    print(f"  wrote:  {outputs.analysis_path}")
    if outputs.scaffold_root is not None:
        print(f"  scaffold: {outputs.scaffold_root} ({len(outputs.scaffold_paths)} files, anchors injected)")
    else:
        print("  (pass --pack + --evaluator to also scaffold an anchor-annotated kata-sn<N>/)")
    return 0


def build_output_root_env() -> str:
    from kata_forge.build import OUTPUT_ROOT_ENV

    return OUTPUT_ROOT_ENV


def _git_rev(path: Path) -> str:
    """The checkout's HEAD, or "unknown". Read, never asked for: pasting four hashes by hand is how
    a bundle ends up pinned to a core it was not built against."""
    import subprocess

    try:
        result = subprocess.run(["git", "-C", str(path), "rev-parse", "HEAD"],
                                capture_output=True, text=True, timeout=30, check=False)
    except (OSError, subprocess.SubprocessError):
        return "unknown"
    return result.stdout.strip() or "unknown"


def _derive_spec(args: argparse.Namespace):
    """Fill in pack/evaluator/subnet from whatever the operator did supply."""
    from kata_forge.spec import SubnetSpec
    from kata_forge.trusted_input import parse_canonical_github_url

    subnet = args.subnet
    pack, evaluator = args.pack, args.evaluator
    if pack:
        subnet = subnet or _subnet_from_pack(pack)
    if subnet is None:
        raise ValueError("pass --subnet, or a --pack of the form sn<N>__<slug>")
    if not pack:
        slug = (parse_canonical_github_url(args.repo).repo.lower().replace("-", "_")
                if args.repo else f"sn{subnet}")
        pack = f"sn{subnet}__{slug}"
    if not evaluator:
        evaluator = pack.replace("__", "_")
    return SubnetSpec(subnet_number=subnet, pack=pack, evaluator_id=evaluator,
                      mode=args.mode, name=args.name)


def _handle_build(args: argparse.Namespace) -> int:
    """Run the S7 chain. Exit 0 for an installable bundle, 2 for a refusal or a rejected input."""
    import json
    import os

    from kata_forge.build import OUTPUT_ROOT_ENV, BuildError, build
    from kata_forge.pinned_fetch import PinnedFetchError
    from kata_forge.trusted_input import TrustedInputError

    output_root = args.out or os.environ.get(OUTPUT_ROOT_ENV)
    if not output_root:
        print(f"kata-forge: error: pass --out or set {OUTPUT_ROOT_ENV}", file=sys.stderr)
        return 2

    here = Path(__file__).resolve().parents[2]
    kata_root = Path(args.kata_root) if args.kata_root else here / "kata"
    kata_bot_root = Path(args.kata_bot_root) if args.kata_bot_root else here / "kata-bot"

    try:
        spec = _derive_spec(args)
        kata_tree_hash = args.kata_tree_hash or _kata_tree_hash(kata_root)
        parity = json.loads(Path(args.parity_json).read_text()) if args.parity_json else None
        result = build(
            output_root=output_root, spec=spec, repo=args.repo,
            # --subnet also names the lane. When --repo resolves the input, the number is
            # spec-only; passing it as a resolver input too would trip the mutual exclusion.
            subnet=None if args.repo else args.subnet,
            catalog_path=args.catalog, commit=args.commit, new_attempt=args.new_attempt,
            allow_gpu=args.allow_gpu,
            kata_rev=args.kata_rev or _git_rev(kata_root),
            kata_bot_rev=args.kata_bot_rev or _git_rev(kata_bot_root),
            kata_forge_rev=args.kata_forge_rev or _git_rev(Path(__file__).resolve().parents[1]),
            kata_tree_hash=kata_tree_hash,
            source_repo=args.source_repo,
            plugin_source=args.plugin_src,
            vendor_closure_files=args.vendor_closure_files,
            vendor_entangled=[v for v in args.vendor_entangled.split(",") if v.strip()],
            parity=parity,
        )
    except (TrustedInputError, PinnedFetchError, BuildError, ValueError, OSError) as error:
        print(f"kata-forge: REFUSE / NEEDS-HUMAN: {error}", file=sys.stderr)
        return 2

    print(f"kata-forge: {result.state} {result.build_id}")
    print(f"  mode:   {result.mode}")
    print(f"  bundle: {result.bundle_dir}")
    if result.reused:
        print("  (existing build for identical inputs; pass --new-attempt to rebuild)")
    if result.unresolved_methods:
        print(f"  UNRESOLVED: {', '.join(result.unresolved_methods)}")
        print("  reviewable, but the installer will refuse it until these are written")
    if result.installable:
        print(f"  next: sudo kata-subnets stage --bundle {result.bundle_dir}")
    return 0 if result.installable else 2


def _kata_tree_hash(kata_root: Path) -> str:
    """The installed core's content hash, computed the same way the installer computes it."""
    import hashlib

    base = kata_root / "kata"
    if not base.is_dir():
        raise ValueError(f"no kata core at {base}; pass --kata-root or --kata-tree-hash")
    entries = []
    for path in sorted(base.rglob("*")):
        if path.is_file() and not path.is_symlink():
            entries.append((str(path.relative_to(base)).replace("\\", "/"),
                            hashlib.sha256(path.read_bytes()).hexdigest()))
    digest = hashlib.sha256()
    for rel, file_hash in sorted(entries):
        digest.update(rel.encode("utf-8"))
        digest.update(b"\0")
        digest.update(file_hash.encode("ascii"))
        digest.update(b"\n")
    return digest.hexdigest()


def _subnet_from_pack(pack: str) -> int:
    """``sn44__poker44`` -> 44. The pack already encodes the subnet, so it need not be repeated."""
    import re

    match = re.match(r"^sn(\d+)__", pack or "")
    if not match:
        raise ValueError(f"--pack must look like sn<N>__<slug>, got {pack!r}")
    return int(match.group(1))


def _handle_decide(args: argparse.Namespace) -> int:
    """Run the S5 decision pipeline. Exit 0 for VENDOR/CLONE, 2 for REFUSE, 2 for a refused input.

    A REFUSE is a successful RUN with a negative RESULT, so it still writes a decision record — that
    record is exactly what a human reads to decide whether to override.
    """
    from kata_forge.onboard import run_decision_pipeline
    from kata_forge.pinned_fetch import PinnedFetchError
    from kata_forge.trusted_input import TrustedInputError

    try:
        result = run_decision_pipeline(
            repo=args.repo,
            subnet=args.subnet,
            catalog_path=args.catalog,
            work_dir=args.work_dir,
            out_dir=args.out,
            commit=args.commit,
            allow_gpu=args.allow_gpu,
        )
    except (TrustedInputError, PinnedFetchError) as error:
        # No record is written: without a canonical, pinned source there is nothing to record ABOUT.
        print(f"kata-forge: REFUSE / NEEDS-HUMAN: {error}", file=sys.stderr)
        return 2

    decision = result.decision
    print(f"kata-forge: {decision.mode} {result.canonical.url}@{result.pinned.commit[:12]}")
    for reason in decision.reasons:
        print(f"  - {reason}")
    print(f"  record: {result.record_path}")
    return 2 if decision.refused else 0


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "extract":  # extract takes --repo/--subnet, not a full spec
        return _run_extract(args)
    if args.command == "survey":  # survey takes repo paths, not a spec
        return _run_survey(args)
    if args.command == "decide":  # S5 takes a canonical repo/subnet, not a spec
        return _handle_decide(args)
    if args.command == "build":  # S7 builds its own spec from --pack/--evaluator
        return _handle_build(args)
    try:
        spec = spec_from_args(args)
    except SpecError as error:
        print(f"kata-forge: error: {error}", file=sys.stderr)
        return 2

    if args.command == "new":
        from kata_forge.generator import GeneratorError, generate

        try:
            written = generate(spec, args.out, force=args.force)
        except GeneratorError as error:
            print(f"kata-forge: error: {error}", file=sys.stderr)
            return 2
        target = Path(args.out).expanduser().resolve() / spec.repo_name
        print(f"kata-forge: scaffolded {spec.repo_name} at {target} ({len(written)} files)")
        for path in written:
            print(f"  {path.relative_to(target.parent)}")
        print("  next: fill sample_problems / run_candidate / score / compare (see kata-sn126)")
        return 0
    if args.command == "lane-config":
        from kata_forge.lane_config import (
            editable_path,
            env_patch,
            lane_entry,
            render_snippet,
            secret_placeholder_block,
        )

        allowed_hosts = required_secrets = None
        if args.repo:  # paid/networked subnet: derive the egress allowlist + secret names
            from kata_forge.secrets import extract_secrets

            secret_report = extract_secrets(args.repo)
            allowed_hosts = secret_report.allowed_hosts
            required_secrets = secret_report.required_secrets

        path = editable_path(spec, args.srv_root)
        entry = lane_entry(
            spec,
            org=args.org,
            release_path=args.release_path or None,
            sample_size=args.sample_size or None,
            allowed_hosts=allowed_hosts,
            required_secrets=required_secrets,
        )
        print(render_snippet(spec, entry, path))
        placeholders = secret_placeholder_block(required_secrets or [], spec.subnet_number)
        if placeholders:
            print("\n# 5. add these secret placeholders to the .env and fill them in:")
            for line in placeholders:
                print(f"     {line}")
        if args.env:
            env_file = Path(args.env).expanduser()
            if not env_file.is_file():
                print(f"kata-forge: error: no .env at {args.env}", file=sys.stderr)
                return 2
            patch = env_patch(
                env_file.read_text(encoding="utf-8"), entry, path,
                secret_placeholders=required_secrets,
            )
            if not patch:
                print("\nkata-forge: .env already has this lane; no change needed.")
            elif args.out:
                Path(args.out).expanduser().write_text(patch, encoding="utf-8")
                print(f"\nkata-forge: wrote reviewable patch to {args.out} (apply with `git apply`)")
            else:
                print("\n--- reviewable patch (apply with `git apply`) ---")
                print(patch, end="")
        return 0
    return 0


if __name__ == "__main__":
    sys.exit(main())
