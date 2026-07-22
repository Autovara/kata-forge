"""Resolve a subnet number to its validator repo via the Bittensor chain (the M3.1 hook).

``--repo`` stays the primary path; this fills the ``--subnet N`` case by asking the chain for the
subnet's registered GitHub repo (its subnet identity / commitment). ``bittensor`` is a **lazy,
optional** import: absent or unreachable, we raise the same clear ``RepoResolveError`` that tells
the operator to pass ``--repo`` -- kata-forge core never hard-depends on the chain. The chain
client is injectable so the resolver is testable offline, and URL extraction is defensive (attrs
*and* a github regex over the identity) because the identity schema varies across bittensor versions.
"""

from __future__ import annotations

import re
from collections.abc import Callable

from kata_forge.resolver import RepoResolveError, SubnetResolver

#: netuid -> repo url (or None if the subnet registered none). Injectable for tests.
ChainClient = Callable[[int], "str | None"]

_GITHUB = re.compile(r"https?://github\.com/[\w.-]+/[\w.-]+")
_URL_ATTRS = ("github_repo", "subnet_repo", "repo", "repo_url", "url", "github", "subnet_url")


def _github_url_from_identity(identity: object) -> str | None:
    """Pull a github repo url out of a subnet-identity object/dict, however it is shaped."""
    if identity is None:
        return None
    for attr in _URL_ATTRS:
        value = identity.get(attr) if isinstance(identity, dict) else getattr(identity, attr, None)
        if isinstance(value, str) and value.strip():
            match = _GITHUB.search(value)
            return match.group(0) if match else value.strip()
    # no known field matched: scan every string field (then the repr) for a github url.
    if isinstance(identity, dict):
        values: object = identity.values()
    elif hasattr(identity, "__dict__"):
        values = vars(identity).values()
    else:
        values = ()
    for value in (*values, str(identity)):
        if isinstance(value, str):
            match = _GITHUB.search(value)
            if match:
                return match.group(0)
    return None


def bittensor_chain_client(network: str = "finney") -> ChainClient:
    """A chain client backed by ``bittensor`` (lazy import; clear error if unavailable)."""
    try:
        import bittensor as bt
    except ImportError as error:  # keep core pure -- bittensor is an optional extra
        raise RepoResolveError(
            "bittensor is not installed, so --subnet cannot be resolved from the chain; "
            "`pip install bittensor` or pass --repo <url|path>"
        ) from error

    try:
        subtensor = bt.subtensor(network=network)
    except Exception as error:  # noqa: BLE001 - any connection/setup failure degrades the same way
        raise RepoResolveError(
            f"could not reach the bittensor {network} chain ({error}); pass --repo <url|path>"
        ) from error

    def client(netuid: int) -> str | None:
        getter = getattr(subtensor, "get_subnet_identity", None)
        identity = getter(netuid) if callable(getter) else None
        return _github_url_from_identity(identity)

    return client


def chain_resolver(*, network: str = "finney", client: ChainClient | None = None) -> SubnetResolver:
    """A ``SubnetResolver`` that maps subnet N -> repo url via the chain.

    The client is built lazily on first use so an unavailable chain surfaces through the same
    ``RepoResolveError`` path as ``resolve_repo`` (rc 2 with a "pass --repo" hint), not at import.
    """

    def resolve(netuid: int) -> str | None:
        active = client or bittensor_chain_client(network)
        return active(netuid)

    return resolve
