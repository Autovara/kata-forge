"""S5 end to end: resolve -> fetch -> research -> decide -> record (plan 4.2 steps 0-5).

Exercises the whole chain with a scripted git runner, so no network, no clone, and no upstream code
execution is involved.
"""
from __future__ import annotations

import json

import pytest

from kata_forge.cli import main
from kata_forge.decision import CLONE, REFUSE, VENDOR
from kata_forge.onboard import INTEGRATION_DECISION_FILENAME, run_decision_pipeline
from kata_forge.parity import ParityResult
from kata_forge.trusted_input import TrustedInputError

GOOD = "https://github.com/Autovara/kata"
FULL_SHA = "d" * 40
MIT = "MIT License\n\nPermission is hereby granted, free of charge, to any person obtaining a copy\n"


class _ScriptedGit:
    """Materialises a fake upstream tree on `clone`, so the research steps have something to read."""

    def __init__(self, files: dict[str, str], *, head=FULL_SHA):
        self.files, self.head = files, head

    def __call__(self, args):
        sub = next((a for a in args if a in ("clone", "checkout", "rev-parse")), None)
        if sub == "clone":
            from pathlib import Path
            dest = Path(args[-1])
            for rel, text in self.files.items():
                target = dest / rel
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text(text, encoding="utf-8")
            dest.mkdir(parents=True, exist_ok=True)
            return (0, "", "")
        if sub == "checkout":
            return (0, "", "")
        return (0, self.head, "")


def _run(tmp_path, files, **over):
    kwargs = dict(repo=GOOD, work_dir=tmp_path / "work", out_dir=tmp_path / "out",
                  git_runner=_ScriptedGit(files))
    kwargs.update(over)
    return run_decision_pipeline(**kwargs)


FREE_REPO = {
    "LICENSE": MIT,
    "requirements.txt": "numpy\n",
    "scorer.py": "def score(x):\n    return x * 2\n",
}


# ---- the three acceptance outcomes ---------------------------------------------------------------
def test_a_free_permissive_pure_scorer_decides_vendor(tmp_path):
    result = _run(tmp_path, FREE_REPO, vendor_closure_files=2)
    assert result.decision.mode == VENDOR
    assert result.pinned.commit == FULL_SHA
    assert result.record_path.name == INTEGRATION_DECISION_FILENAME


def test_an_entangled_free_repo_with_executed_parity_decides_clone(tmp_path):
    parity = ParityResult(executed=True, matched=True, cases_run=4).as_evidence()
    result = _run(tmp_path, FREE_REPO, vendor_closure_files=50,
                  vendor_entangled=["docker"], parity=parity)
    assert result.decision.mode == CLONE


def test_an_unsatisfiable_repo_decides_refuse_with_a_record(tmp_path):
    result = _run(tmp_path, FREE_REPO, vendor_closure_files=50, vendor_entangled=["docker"])
    assert result.decision.mode == REFUSE
    record = json.loads(result.record_path.read_text())
    assert record["mode"] == REFUSE and record["reasons"], "a refusal must carry a precise reason"


# ---- gates fire on real scanned evidence ---------------------------------------------------------
def test_an_embedded_credential_in_the_fetched_tree_refuses(tmp_path):
    leaked = "ghp_" + "E" * 36
    files = {**FREE_REPO, "settings.py": f"TOKEN = '{leaked}'\n"}
    result = _run(tmp_path, files, vendor_closure_files=1)

    assert result.decision.mode == REFUSE
    assert "before any AI input" in " ".join(result.decision.reasons)
    # The record names the leak without repeating it.
    body = result.record_path.read_text()
    assert leaked not in body and "settings.py" in body


def test_a_paid_dependency_in_the_fetched_tree_refuses(tmp_path):
    files = {**FREE_REPO, "requirements.txt": "openai\n"}
    result = _run(tmp_path, files, vendor_closure_files=1)
    assert result.decision.mode == REFUSE
    assert "not free" in " ".join(result.decision.reasons)


def test_a_copyleft_licence_blocks_vendor_but_clone_still_reachable(tmp_path):
    files = {**FREE_REPO, "LICENSE": "GNU GENERAL PUBLIC LICENSE\nVersion 3, 29 June 2007\n"}
    assert _run(tmp_path, files, vendor_closure_files=1).decision.mode == REFUSE

    parity = ParityResult(executed=True, matched=True, cases_run=2).as_evidence()
    result = _run(tmp_path, files, vendor_closure_files=1, parity=parity,
                  out_dir=tmp_path / "out2", work_dir=tmp_path / "work2")
    assert result.decision.mode == CLONE


def test_the_record_carries_the_full_pinned_provenance(tmp_path):
    record = json.loads(_run(tmp_path, FREE_REPO, vendor_closure_files=1).record_path.read_text())
    source = record["evidence"]["source"]
    assert source["url"] == GOOD and source["commit"] == FULL_SHA
    assert record["evidence"]["license"]["spdx"] == "MIT"


# ---- input refusal happens before any fetch ------------------------------------------------------
@pytest.mark.parametrize("bad", ["/srv/kata", "git@github.com:o/r.git", "https://gitlab.com/o/r"])
def test_a_non_canonical_input_never_reaches_the_fetch(tmp_path, bad):
    def _must_not_run(_args):
        pytest.fail("a non-canonical input must be refused before any clone")

    with pytest.raises(TrustedInputError):
        run_decision_pipeline(repo=bad, work_dir=tmp_path / "w", out_dir=tmp_path / "o",
                              git_runner=_must_not_run)


# ---- the CLI surface -----------------------------------------------------------------------------
def test_cli_refuses_a_non_canonical_repo(tmp_path, capsys):
    code = main(["decide", "--repo", "/srv/kata",
                 "--work-dir", str(tmp_path / "w"), "--out", str(tmp_path / "o")])
    assert code == 2
    assert "REFUSE / NEEDS-HUMAN" in capsys.readouterr().err


def test_cli_refuses_both_repo_and_subnet(tmp_path, capsys):
    code = main(["decide", "--repo", GOOD, "--subnet", "60",
                 "--work-dir", str(tmp_path / "w"), "--out", str(tmp_path / "o")])
    assert code == 2
    assert "mutually exclusive" in capsys.readouterr().err


def test_cli_refuses_a_subnet_without_a_catalog(tmp_path, capsys):
    code = main(["decide", "--subnet", "60",
                 "--work-dir", str(tmp_path / "w"), "--out", str(tmp_path / "o")])
    assert code == 2
    assert "catalog" in capsys.readouterr().err
