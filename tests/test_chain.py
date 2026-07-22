from __future__ import annotations

import importlib.util

import pytest

from kata_forge.chain import (
    _github_url_from_identity,
    bittensor_chain_client,
    chain_resolver,
)
from kata_forge.resolver import RepoResolveError, resolve_repo

_HAS_BITTENSOR = importlib.util.find_spec("bittensor") is not None


class _Identity:
    def __init__(self, **kw):
        self.__dict__.update(kw)


def test_github_url_from_identity_attr() -> None:
    ident = _Identity(github_repo="https://github.com/Autovara/poker44")
    assert _github_url_from_identity(ident) == "https://github.com/Autovara/poker44"


def test_github_url_from_identity_dict_and_regex_fallback() -> None:
    assert _github_url_from_identity({"url": "https://github.com/x/y"}) == "https://github.com/x/y"
    # a url buried in an unrelated field -> regex scan of the repr finds it
    assert _github_url_from_identity(_Identity(description="see https://github.com/a/b for code")) == (
        "https://github.com/a/b"
    )


def test_github_url_from_identity_none() -> None:
    assert _github_url_from_identity(None) is None
    assert _github_url_from_identity(_Identity(name="poker44")) is None


def test_chain_resolver_with_injected_client() -> None:
    resolver = chain_resolver(client=lambda netuid: f"https://github.com/org/sn{netuid}")
    assert resolver(126) == "https://github.com/org/sn126"


def test_resolve_repo_uses_chain_resolver_for_local_path(tmp_path) -> None:
    import subprocess

    repo = tmp_path / "repo"
    repo.mkdir()
    subprocess.run(["git", "init", "-q", str(repo)], check=True)
    resolver = chain_resolver(client=lambda netuid: str(repo))
    resolved = resolve_repo(subnet=126, resolver=resolver)
    assert resolved.path == repo.resolve()


def test_chain_resolver_none_result_errors_clearly() -> None:
    resolver = chain_resolver(client=lambda netuid: None)  # subnet registered no repo
    with pytest.raises(RepoResolveError, match="no repo for subnet 999"):
        resolve_repo(subnet=999, resolver=resolver)


@pytest.mark.skipif(_HAS_BITTENSOR, reason="bittensor installed; testing the missing-lib path")
def test_missing_bittensor_degrades_clearly() -> None:
    with pytest.raises(RepoResolveError, match="bittensor is not installed"):
        bittensor_chain_client()
