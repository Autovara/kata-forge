from __future__ import annotations

from pathlib import Path

import pytest

from kata_forge.secrets import extract_secrets, scan_env_vars

POKER44 = Path("/tmp/poker44-research")


def _write(repo: Path, rel: str, body: str) -> None:
    (repo / rel).parent.mkdir(parents=True, exist_ok=True)
    (repo / rel).write_text(body, encoding="utf-8")


def test_scan_env_vars_keeps_secrets_drops_config(tmp_path) -> None:
    _write(
        tmp_path,
        "cfg.py",
        'import os\n'
        'a = os.getenv("NETUID")\n'
        'b = os.getenv("WALLET_NAME")\n'
        'c = os.getenv("HOTKEY")\n'  # ends in KEY but no underscore -> not a secret
        'd = os.environ["OPENAI_API_KEY"]\n'
        'e = os.environ.get("APIFY_TOKEN")\n',
    )
    assert scan_env_vars(tmp_path) == ["APIFY_TOKEN", "OPENAI_API_KEY"]


def test_extract_paid_repo(tmp_path) -> None:
    _write(
        tmp_path,
        "agent.py",
        'import os, requests\n'
        'KEY = os.environ["OPENAI_API_KEY"]\n'
        'requests.post("https://api.openai.com/v1/chat/completions")\n',
    )
    report = extract_secrets(tmp_path)
    assert "OPENAI_API_KEY" in report.required_secrets
    assert "api.openai.com" in report.allowed_hosts
    assert report.providers == ["openai"]
    assert report.paid_providers == ["openai"]


def test_pydantic_field_env_and_host_provider(tmp_path) -> None:
    _write(tmp_path, "settings.py", 'token: str = Field(..., env="APIFY_TOKEN")\n')
    _write(tmp_path, "client.py", 'URL = "https://api.anthropic.com/v1/messages"\n')
    report = extract_secrets(tmp_path)
    assert "APIFY_TOKEN" in report.required_secrets
    assert "apify" in report.providers  # from the pydantic env var
    assert "anthropic" in report.providers  # from the host, with no env var


def test_free_tier_provider_not_counted_paid(tmp_path) -> None:
    _write(tmp_path, "log.py", 'import os\nk = os.getenv("WANDB_API_KEY")\n')
    report = extract_secrets(tmp_path)
    assert report.providers == ["wandb"]
    assert report.paid_providers == []  # wandb is free-tier


def test_unknown_key_is_required_but_unattributed(tmp_path) -> None:
    _write(tmp_path, "x.py", 'import os\nk = os.getenv("ACME_PRIVATE_KEY")\n')
    report = extract_secrets(tmp_path)
    assert "ACME_PRIVATE_KEY" in report.required_secrets  # still flagged
    assert report.providers == []  # but not attributed to a known provider


@pytest.mark.skipif(not POKER44.exists(), reason="poker44 clone not present")
def test_poker44_has_no_paid_provider() -> None:
    report = extract_secrets(POKER44)
    assert report.paid_providers == []  # public no-auth benchmark -> FREE (matches feasibility)
    assert "api.poker44.net" in report.allowed_hosts
    assert "WANDB_API_KEY" in report.required_secrets
    assert report.providers == ["wandb"]
