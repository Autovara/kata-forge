from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from kata_forge.cli import main
from kata_forge.resolver import (
    RepoResolveError,
    registry_resolver,
    resolve_repo,
)

POKER44 = Path("/tmp/poker44-research")


def _make_git_repo(path: Path) -> str:
    path.mkdir(parents=True, exist_ok=True)
    subprocess.run(["git", "init", "-q", str(path)], check=True)
    (path / "f.txt").write_text("hi", encoding="utf-8")
    env = ["-c", "user.email=t@t", "-c", "user.name=t"]
    subprocess.run(["git", "-C", str(path), "add", "-A"], check=True)
    subprocess.run(["git", "-C", str(path), *env, "commit", "-q", "-m", "init"], check=True)
    return subprocess.run(
        ["git", "-C", str(path), "rev-parse", "HEAD"],
        capture_output=True, text=True, check=False,
    ).stdout.strip()


def test_resolve_local_git_repo(tmp_path) -> None:
    head = _make_git_repo(tmp_path / "repo")
    resolved = resolve_repo(repo=str(tmp_path / "repo"))
    assert resolved.path == (tmp_path / "repo").resolve()
    assert resolved.commit == head
    assert resolved.was_cloned is False


def test_resolve_local_non_git_dir_has_no_commit(tmp_path) -> None:
    (tmp_path / "plain").mkdir()
    assert resolve_repo(repo=str(tmp_path / "plain")).commit is None


def test_subnet_without_resolver_errors_clearly() -> None:
    with pytest.raises(RepoResolveError, match="no subnet->repo resolver"):
        resolve_repo(subnet=126)


def test_subnet_with_registry_resolver(tmp_path) -> None:
    _make_git_repo(tmp_path / "repo")
    resolver = registry_resolver({126: str(tmp_path / "repo")})
    assert resolve_repo(subnet=126, resolver=resolver).path == (tmp_path / "repo").resolve()
    with pytest.raises(RepoResolveError, match="no repo for subnet 999"):
        resolve_repo(subnet=999, resolver=resolver)


def test_no_repo_no_subnet_errors() -> None:
    with pytest.raises(RepoResolveError, match="provide --repo"):
        resolve_repo()


def test_clone_path_with_injected_git(tmp_path) -> None:
    # Exercise the URL/clone branch without network, via an injected git runner.
    def fake_git(args: list[str]) -> tuple[int, str, str]:
        if args[0] == "clone":
            dest = Path(args[-1])
            dest.mkdir(parents=True, exist_ok=True)
            (dest / "x").write_text("y", encoding="utf-8")
            return 0, "", ""
        if "rev-parse" in args:
            return 0, "deadbeefcafe", ""
        return 0, "", ""

    resolved = resolve_repo(
        repo="https://example.com/foo.git", work_dir=tmp_path, git_runner=fake_git
    )
    assert resolved.was_cloned is True
    assert resolved.commit == "deadbeefcafe"
    assert resolved.path.name == "foo"


def test_cli_extract_local_repo(tmp_path, capsys) -> None:
    _make_git_repo(tmp_path / "repo")
    assert main(["extract", "--repo", str(tmp_path / "repo")]) == 0
    assert "commit:" in capsys.readouterr().out


def test_cli_extract_subnet_without_repo_falls_back_to_chain(capsys) -> None:
    # --subnet with no --repo now tries the chain resolver; with no chain reachable here it
    # degrades cleanly to rc 2 with the "pass --repo" hint (bittensor missing or unreachable).
    assert main(["extract", "--subnet", "126"]) == 2
    assert "--repo" in capsys.readouterr().err


@pytest.mark.skipif(not POKER44.exists(), reason="poker44 clone not present")
def test_resolves_the_real_poker44_clone() -> None:
    resolved = resolve_repo(repo=str(POKER44))
    assert resolved.commit == "2ceac436e896b8c9a3b4991ceb6d0644c8ad8d9a"  # the pinned commit
    assert resolved.was_cloned is False
