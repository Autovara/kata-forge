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
        # F4 emits the KATA_LANES snippet + patch here.
        print(
            f"kata-forge: validated lane {spec.pack} (evaluator={spec.evaluator_id}). "
            "Config emission lands in F4."
        )
        return 0
    return 0


if __name__ == "__main__":
    sys.exit(main())
