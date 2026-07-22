from __future__ import annotations

from pathlib import Path

import pytest

from kata_forge.cost import estimate_cost

POKER44 = Path("/tmp/poker44-research")


def _write(repo: Path, rel: str, body: str) -> None:
    (repo / rel).parent.mkdir(parents=True, exist_ok=True)
    (repo / rel).write_text(body, encoding="utf-8")


def test_metered_from_env_key_and_host(tmp_path) -> None:
    _write(tmp_path, "a.py", 'import os\nk=os.environ["OPENAI_API_KEY"]\nU="https://api.openai.com/v1"')
    report = estimate_cost(tmp_path)
    assert report.cost_class == "METERED"
    assert report.paid_providers == ["openai"]


def test_metered_from_imported_sdk_without_key(tmp_path) -> None:
    _write(tmp_path, "requirements.txt", "openai>=1.0\nnumpy\n")
    report = estimate_cost(tmp_path)  # SDK imported/declared, no env read -> still metered
    assert report.cost_class == "METERED"
    assert "openai" in report.paid_providers


def test_gpu_is_free_on_money_but_flags_gpu(tmp_path) -> None:
    _write(tmp_path, "requirements.txt", "torch\nnumpy\n")
    report = estimate_cost(tmp_path)
    assert report.cost_class == "FREE"  # GPU is compute, not a paid key
    assert report.needs_gpu is True
    assert "needs GPU" in report.summary


def test_gated_data_is_low(tmp_path) -> None:
    _write(tmp_path, "requirements.txt", "datasets\nnumpy\n")
    report = estimate_cost(tmp_path)
    assert report.cost_class == "LOW"
    assert any("gated data" in n for n in report.notes)


def test_aws_is_low(tmp_path) -> None:
    _write(tmp_path, "requirements.txt", "boto3\n")
    report = estimate_cost(tmp_path)
    assert report.cost_class == "LOW"
    assert report.paid_providers == ["aws"]


def test_free_tier_wandb_stays_free_no_note(tmp_path) -> None:
    _write(tmp_path, "log.py", 'import os\nk=os.getenv("WANDB_API_KEY")\n')
    report = estimate_cost(tmp_path)
    assert report.cost_class == "FREE"
    assert report.notes == []  # wandb is free-tier, not an unattributed secret


@pytest.mark.skipif(not POKER44.exists(), reason="poker44 clone not present")
def test_poker44_is_free_with_internal_secret_note() -> None:
    report = estimate_cost(POKER44)
    assert report.cost_class == "FREE"
    assert report.needs_gpu is False
    assert report.paid_providers == []
    assert any("unattributed required secrets" in n for n in report.notes)  # verathos/internal flagged
