from __future__ import annotations

from pathlib import Path

import pytest

from kata_forge.batch import render_survey_table, survey, survey_repo
from kata_forge.cli import main

POKER44 = Path("/tmp/poker44-research")
TEMPLATE = Path("/tmp/kf-2nd/bittensor-subnet-template")


def _write(repo: Path, rel: str, body: str) -> None:
    (repo / rel).parent.mkdir(parents=True, exist_ok=True)
    (repo / rel).write_text(body, encoding="utf-8")


def _free_complete_repo(repo: Path) -> None:
    _write(repo, "requirements.txt", "numpy\nscikit-learn\n")
    _write(repo, "score.py", "def reward(y_pred, y_true) -> tuple[float, dict]:\n    return 1.0, {}\n")
    _write(repo, "net.py", 'BASE = "https://api.sub.net/benchmark"\n')
    _write(repo, "syn.py", "import bittensor as bt\nclass S(bt.Synapse): pass\n")


def test_survey_ranks_free_complete_above_gpu(tmp_path) -> None:
    good = tmp_path / "good-subnet"
    _free_complete_repo(good)
    gpu = tmp_path / "gpu-subnet"
    _write(gpu, "requirements.txt", "torch\n")
    _write(gpu, "score.py", "def reward(a, b) -> float:\n    return 1.0\n")

    rows = survey([str(good), str(gpu)])
    assert rows[0].label == "good-subnet"  # FREE + all anchors + no GPU ranks first
    assert rows[0].effort == "LOW"
    assert rows[0].score > rows[1].score
    assert rows[1].needs_gpu is True


def test_survey_repo_counts_anchors(tmp_path) -> None:
    _free_complete_repo(tmp_path / "r")
    row = survey_repo(tmp_path / "r", subnet=42)
    assert row.subnet == 42
    assert row.anchors_found == 3
    assert row.cost_class == "FREE"


def test_survey_bad_repo_is_error_row_ranked_last(tmp_path) -> None:
    _free_complete_repo(tmp_path / "ok")
    rows = survey([str(tmp_path / "ok"), {"path": str(tmp_path / "does-not-exist"), "subnet": 9}])
    assert rows[-1].label in {"does-not-exist", str(tmp_path / "does-not-exist")}
    # a missing repo simply has no anchors/deps; it must never outrank a real candidate
    assert rows[0].label == "ok"


def test_render_survey_table_has_rows(tmp_path) -> None:
    _free_complete_repo(tmp_path / "r")
    table = render_survey_table(survey([str(tmp_path / "r")]))
    assert "onboarding backlog" in table
    assert "| 1 | r |" in table
    assert "✓✓✓" in table  # all three anchors found


def test_cli_survey_prints_table(tmp_path, capsys) -> None:
    _free_complete_repo(tmp_path / "r")
    assert main(["survey", str(tmp_path / "r")]) == 0
    assert "onboarding backlog" in capsys.readouterr().out


@pytest.mark.skipif(not (POKER44.exists() and TEMPLATE.exists()), reason="clones not present")
def test_survey_poker44_above_template() -> None:
    rows = survey([{"path": str(TEMPLATE), "subnet": 1}, {"path": str(POKER44), "subnet": 126}])
    assert rows[0].subnet == 126  # Poker44 (FREE, all anchors) beats the GPU template
    assert rows[0].effort == "LOW"
    assert any(r.subnet == 1 and r.needs_gpu for r in rows)
