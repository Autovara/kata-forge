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

    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
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
        from kata_forge.lane_config import editable_path, env_patch, lane_entry, render_snippet

        path = editable_path(spec, args.srv_root)
        entry = lane_entry(
            spec,
            org=args.org,
            release_path=args.release_path or None,
            sample_size=args.sample_size or None,
        )
        print(render_snippet(spec, entry, path))
        if args.env:
            env_file = Path(args.env).expanduser()
            if not env_file.is_file():
                print(f"kata-forge: error: no .env at {args.env}", file=sys.stderr)
                return 2
            patch = env_patch(env_file.read_text(encoding="utf-8"), entry, path)
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
