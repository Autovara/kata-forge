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
