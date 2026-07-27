"""S5: trusted input + pinned fetch (plan 4.1).

The production build path must not inherit ``extract``'s permissive local-path behaviour: whatever
this resolves to is what gets cloned, read by an AI, scaffolded, and eventually installed.
"""
from __future__ import annotations

import json

import pytest

from kata_forge.pinned_fetch import PinnedFetchError, fetch_pinned
from kata_forge.trusted_input import (
    CATALOG_SCHEMA_VERSION,
    CanonicalRepo,
    TrustedInputError,
    parse_canonical_github_url,
    resolve_subnet,
    resolve_trusted_input,
)

GOOD = "https://github.com/Autovara/kata"


# ---- canonical URL parsing -----------------------------------------------------------------------
@pytest.mark.parametrize("raw,owner,repo", [
    (GOOD, "Autovara", "kata"),
    ("https://github.com/Autovara/kata.git", "Autovara", "kata"),
    ("https://github.com/Autovara/kata/", "Autovara", "kata"),
    ("https://github.com/Bitsec-AI/sandbox", "Bitsec-AI", "sandbox"),
    ("https://github.com/o/repo.with.dots", "o", "repo.with.dots"),
])
def test_canonical_urls_parse(raw, owner, repo):
    parsed = parse_canonical_github_url(raw)
    assert parsed == CanonicalRepo(owner=owner, repo=repo)
    assert parsed.url == f"https://github.com/{owner}/{repo}"  # one normalized spelling


@pytest.mark.parametrize("raw", [
    "git@github.com:Autovara/kata.git",              # SSH
    "ssh://git@github.com/Autovara/kata",            # SSH
    "http://github.com/Autovara/kata",               # not https
    "file:///srv/kata",                              # local
    "/srv/kata",                                     # bare local path
    "./relative/path",                               # relative local path
    "https://gitlab.com/Autovara/kata",              # wrong host
    "https://github.com.evil.example/Autovara/kata",  # look-alike host
    "https://user:token@github.com/Autovara/kata",   # credential smuggling
    "https://github.com/Autovara",                   # one segment
    "https://github.com/Autovara/kata/tree/main",    # three segments
    "https://github.com/Autovara/kata?x=1",          # query
    "https://github.com/Autovara/kata#frag",         # fragment
    "https://192.168.0.1/Autovara/kata",             # IP literal
    "https://github.com//kata",                      # empty owner segment
    "https://github.com/-bad/kata",                  # invalid owner
    "https://github.com/Autovara/..",                # traversal-ish repo name
    "",
    None,
    42,
])
def test_non_canonical_input_refuses(raw):
    """A private or non-GitHub source is REFUSE / NEEDS-HUMAN -- never normalised into something
    plausible and then fetched."""
    with pytest.raises(TrustedInputError):
        parse_canonical_github_url(raw)


def test_identity_is_case_insensitive():
    """GitHub treats owner/repo case-insensitively, so these are ONE repository and must not be able
    to appear as two catalog entries or two lanes."""
    a = parse_canonical_github_url("https://github.com/Autovara/Kata")
    b = parse_canonical_github_url("https://github.com/autovara/kata")
    assert a.identity == b.identity
    assert a.url != b.url  # the recorded spelling is preserved verbatim


# ---- local subnet catalog ------------------------------------------------------------------------
def _catalog(tmp_path, subnets, *, schema_version=CATALOG_SCHEMA_VERSION):
    path = tmp_path / "subnet-catalog.json"
    path.write_text(json.dumps({"schema_version": schema_version, "subnets": subnets}),
                    encoding="utf-8")
    return path


def test_catalog_resolves_exactly_one_entry(tmp_path):
    path = _catalog(tmp_path, [{"subnet_id": 60, "validator_repo": "https://github.com/Bitsec-AI/sandbox"}])
    assert resolve_subnet(60, path).identity == "bitsec-ai/sandbox"


def test_unknown_subnet_refuses_and_names_the_escape_hatch(tmp_path):
    path = _catalog(tmp_path, [{"subnet_id": 60, "validator_repo": GOOD}])
    with pytest.raises(TrustedInputError, match="--repo"):
        resolve_subnet(99, path)


def test_duplicate_subnet_refuses_the_whole_catalog(tmp_path):
    """Ambiguity must not be resolved by taking either row: that is how a wrong repo gets fetched."""
    path = _catalog(tmp_path, [
        {"subnet_id": 60, "validator_repo": GOOD},
        {"subnet_id": 60, "validator_repo": "https://github.com/other/repo"},
    ])
    with pytest.raises(TrustedInputError, match="duplicate"):
        resolve_subnet(60, path)


@pytest.mark.parametrize("subnets", [
    [{"subnet_id": 60, "validator_repo": "git@github.com:o/r.git"}],  # non-canonical row
    [{"subnet_id": 0, "validator_repo": GOOD}],                       # invalid id
    [{"subnet_id": True, "validator_repo": GOOD}],                    # bool is not an id
    [{"validator_repo": GOOD}],                                       # missing id
    ["not-an-object"],
])
def test_malformed_catalog_rows_refuse(tmp_path, subnets):
    path = _catalog(tmp_path, subnets)
    with pytest.raises(TrustedInputError):
        resolve_subnet(60, path)


def test_wrong_schema_version_refuses(tmp_path):
    path = _catalog(tmp_path, [{"subnet_id": 60, "validator_repo": GOOD}], schema_version=99)
    with pytest.raises(TrustedInputError, match="schema_version"):
        resolve_subnet(60, path)


def test_missing_catalog_refuses(tmp_path):
    with pytest.raises(TrustedInputError, match="cannot read"):
        resolve_subnet(60, tmp_path / "absent.json")


# ---- mutual exclusion ----------------------------------------------------------------------------
def test_repo_and_subnet_are_mutually_exclusive(tmp_path):
    path = _catalog(tmp_path, [{"subnet_id": 60, "validator_repo": GOOD}])
    with pytest.raises(TrustedInputError, match="mutually exclusive"):
        resolve_trusted_input(repo=GOOD, subnet=60, catalog_path=path)


def test_neither_input_refuses():
    with pytest.raises(TrustedInputError, match="exactly one"):
        resolve_trusted_input()


def test_subnet_without_a_catalog_refuses():
    with pytest.raises(TrustedInputError, match="catalog"):
        resolve_trusted_input(subnet=60)


# ---- pinned fetch --------------------------------------------------------------------------------
FULL_SHA = "a" * 40


class _FakeGit:
    """Records argv and replays scripted results, so the fetch is testable with no network."""

    def __init__(self, *, head=FULL_SHA, clone_rc=0, checkout_rc=0, gitmodules=False):
        self.calls: list[list[str]] = []
        self.head, self.clone_rc, self.checkout_rc = head, clone_rc, checkout_rc
        self.gitmodules = gitmodules
        self.dest: str | None = None

    def __call__(self, args):
        self.calls.append(args)
        sub = next((a for a in args if a in ("clone", "checkout", "rev-parse")), None)
        if sub == "clone":
            self.dest = args[-1]
            from pathlib import Path
            Path(self.dest).mkdir(parents=True, exist_ok=True)
            if self.gitmodules:
                (Path(self.dest) / ".gitmodules").write_text("[submodule]\n", encoding="utf-8")
            return (self.clone_rc, "", "" if self.clone_rc == 0 else "clone failed")
        if sub == "checkout":
            return (self.checkout_rc, "", "" if self.checkout_rc == 0 else "no such ref")
        return (0, self.head, "")


def test_fetch_pins_a_full_sha(tmp_path):
    git = _FakeGit()
    pinned = fetch_pinned(parse_canonical_github_url(GOOD), tmp_path / "src", git_runner=git)
    assert pinned.commit == FULL_SHA and pinned.url == GOOD
    assert pinned.as_evidence() == {"url": GOOD, "commit": FULL_SHA}


def test_fetch_never_recurses_submodules_and_disables_hooks(tmp_path):
    git = _FakeGit()
    fetch_pinned(parse_canonical_github_url(GOOD), tmp_path / "src", git_runner=git)
    flat = [arg for call in git.calls for arg in call]
    assert "--recurse-submodules" not in flat, "a submodule is a second, unreviewed repository"
    assert "core.hooksPath=/dev/null" in flat, "a fetched repo must not be able to run hooks"
    assert "protocol.file.allow=never" in flat


def test_fetch_refuses_a_repo_declaring_submodules(tmp_path):
    git = _FakeGit(gitmodules=True)
    with pytest.raises(PinnedFetchError, match="gitmodules"):
        fetch_pinned(parse_canonical_github_url(GOOD), tmp_path / "src", git_runner=git)


@pytest.mark.parametrize("bad", ["abc123", "a" * 39, "A" * 40, "main", "v1.0", ""])
def test_fetch_refuses_a_non_full_sha_pin(tmp_path, bad):
    """Tags and branches move, so they cannot pin a build."""
    with pytest.raises(PinnedFetchError, match="full 40"):
        fetch_pinned(parse_canonical_github_url(GOOD), tmp_path / "src",
                     commit=bad, git_runner=_FakeGit())


def test_fetch_refuses_a_checkout_mismatch(tmp_path):
    """Recording the requested commit when the tree is elsewhere would make the manifest assert
    something untrue about the tree that was actually scanned."""
    git = _FakeGit(head="b" * 40)
    with pytest.raises(PinnedFetchError, match="mismatch"):
        fetch_pinned(parse_canonical_github_url(GOOD), tmp_path / "src",
                     commit=FULL_SHA, git_runner=git)


def test_fetch_refuses_a_non_git_or_unreachable_source(tmp_path):
    with pytest.raises(PinnedFetchError, match="clone"):
        fetch_pinned(parse_canonical_github_url(GOOD), tmp_path / "src",
                     git_runner=_FakeGit(clone_rc=128))


def test_fetch_refuses_a_missing_commit(tmp_path):
    with pytest.raises(PinnedFetchError, match="check out"):
        fetch_pinned(parse_canonical_github_url(GOOD), tmp_path / "src",
                     commit=FULL_SHA, git_runner=_FakeGit(checkout_rc=1))


def test_fetch_refuses_a_non_empty_destination(tmp_path):
    dest = tmp_path / "src"
    dest.mkdir()
    (dest / "existing").write_text("x", encoding="utf-8")
    with pytest.raises(PinnedFetchError, match="not empty"):
        fetch_pinned(parse_canonical_github_url(GOOD), dest, git_runner=_FakeGit())


@pytest.mark.parametrize("raw", [
    "https://github.com/o/-",        # a leading hyphen reads as a FLAG to most downstream tools
    "https://github.com/o/-rf",
    "https://github.com/o/r..",      # no real GitHub name contains ".."
    "https://github.com/o/..r",
    "https://github.com/o../r",
    "https://github.com:443/o/r",    # an explicit port is not the canonical spelling
])
def test_names_that_are_hostile_downstream_are_refused(raw):
    """The repo name becomes a directory name and an argv element later in the pipeline."""
    with pytest.raises(TrustedInputError):
        parse_canonical_github_url(raw)


def test_the_dot_github_repository_is_still_accepted():
    """A leading dot is legitimate -- owner/.github is a real and common repository -- so the
    leading-hyphen rule must not over-reach into it."""
    assert parse_canonical_github_url("https://github.com/Autovara/.github").repo == ".github"
