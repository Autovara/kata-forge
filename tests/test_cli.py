from __future__ import annotations

import pytest

from kata_forge.cli import build_parser, main

VALID = ["--subnet", "126", "--pack", "sn126__poker44", "--evaluator", "sn126_poker44"]


def test_new_valid_spec_returns_zero(capsys) -> None:
    assert main(["new", *VALID]) == 0
    assert "kata-sn126" in capsys.readouterr().out


def test_lane_config_valid_spec_returns_zero(capsys) -> None:
    assert main(["lane-config", *VALID]) == 0
    assert "sn126__poker44" in capsys.readouterr().out


def test_invalid_spec_returns_two(capsys) -> None:
    rc = main(["new", "--subnet", "126", "--pack", "wrong", "--evaluator", "sn126_poker44"])
    assert rc == 2
    assert "error" in capsys.readouterr().err


def test_missing_subcommand_exits() -> None:
    with pytest.raises(SystemExit):
        build_parser().parse_args([])


def test_missing_required_arg_exits() -> None:
    with pytest.raises(SystemExit):  # argparse rejects the missing --pack/--evaluator
        main(["new", "--subnet", "126"])
