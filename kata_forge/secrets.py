"""Extract the *precise* secrets + egress a paid subnet needs, to fill EnvSpec safely.

M3.2 said "this subnet needs keys"; M4.1 says **which**. We statically find env-var reads
(``os.environ[...]`` / ``getenv(...)`` / pydantic ``Field(env=...)``), keep the secret-looking
ones (``*_KEY`` / ``*_TOKEN`` / ``*_SECRET`` / known provider vars), and collect the external
hosts the code talks to -- so the operator gets an exact ``required_secrets`` list + an
``allowed_hosts`` egress allowlist (never open network) and the provider names behind them. No
value is ever read or emitted -- only names. Config vars (NETUID, WALLET_NAME, HOTKEY) are dropped.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from kata_forge.anchors import iter_repo_hosts

# env-var reads we recognize; each capture group is the variable name.
_ENV_PATTERNS = (
    re.compile(r"""os\.environ\s*\[\s*["']([A-Za-z_][A-Za-z0-9_]*)["']"""),
    re.compile(r"""(?:os\.)?getenv\(\s*["']([A-Za-z_][A-Za-z0-9_]*)["']"""),
    re.compile(r"""os\.environ\.get\(\s*["']([A-Za-z_][A-Za-z0-9_]*)["']"""),
    re.compile(r"""\benv\s*=\s*["']([A-Za-z_][A-Za-z0-9_]*)["']"""),  # pydantic Field(env=...)
)
# A var name is a secret if it ends like one, or is a known provider var.
_SECRET_SUFFIX = ("_KEY", "_TOKEN", "_SECRET", "_PASSWORD", "_PASS", "_CREDENTIAL", "_CREDENTIALS",
                  "_APIKEY", "_ACCESS_KEY", "_PRIVATE_KEY")
_PROVIDER_BY_VAR = {
    "OPENAI_API_KEY": "openai", "ANTHROPIC_API_KEY": "anthropic", "COHERE_API_KEY": "cohere",
    "MISTRAL_API_KEY": "mistral", "GROQ_API_KEY": "groq", "TOGETHER_API_KEY": "together",
    "OPENROUTER_API_KEY": "openrouter", "REPLICATE_API_TOKEN": "replicate",
    "APIFY_TOKEN": "apify", "APIFY_API_TOKEN": "apify", "SCRAPINGDOG_API_KEY": "scrapingdog",
    "SERPAPI_API_KEY": "serpapi", "TAVILY_API_KEY": "tavily", "FIRECRAWL_API_KEY": "firecrawl",
    "HF_TOKEN": "huggingface", "HUGGINGFACE_TOKEN": "huggingface", "HUGGINGFACEHUB_API_TOKEN": "huggingface",
    "AWS_ACCESS_KEY_ID": "aws", "AWS_SECRET_ACCESS_KEY": "aws", "WANDB_API_KEY": "wandb",
    "POKER44_WANDB_API_KEY": "wandb",
}
# host substring -> provider (used both for the allowlist and to infer a provider from URLs).
_PROVIDER_BY_HOST = {
    "api.openai.com": "openai", "openai.azure.com": "openai", "api.anthropic.com": "anthropic",
    "api.cohere": "cohere", "openrouter.ai": "openrouter", "api.groq.com": "groq",
    "api.together": "together", "api.replicate.com": "replicate", "api.apify.com": "apify",
    "api.scrapingdog.com": "scrapingdog", "serpapi.com": "serpapi", "api.tavily.com": "tavily",
    "huggingface.co": "huggingface", "wandb.ai": "wandb",
}
# providers whose key is optional / free-tier (a secret, but not a paid gate).
FREE_TIER_PROVIDERS = frozenset({"wandb"})


@dataclass(frozen=True)
class SecretReport:
    """The exact secrets + egress a repo needs, for a safe EnvSpec."""

    required_secrets: list[str]  # env-var names (never values)
    allowed_hosts: list[str]  # egress allowlist
    providers: list[str]  # inferred provider names (openai, apify, wandb, ...)
    paid_providers: list[str]  # providers minus free-tier ones


def _looks_secret(name: str) -> bool:
    return name in _PROVIDER_BY_VAR or name.endswith(_SECRET_SUFFIX)


def scan_env_vars(repo: str | Path) -> list[str]:
    """Secret-looking env-var names read anywhere in the repo (sorted, unique)."""
    repo = Path(repo).expanduser()
    from kata_forge.anchors import _iter_py  # reuse the same skip-dir walk

    found: set[str] = set()
    for py in _iter_py(repo):
        text = py.read_text(encoding="utf-8", errors="ignore")
        for pattern in _ENV_PATTERNS:
            for name in pattern.findall(text):
                if _looks_secret(name):
                    found.add(name)
    return sorted(found)


def _provider_for(var: str) -> str | None:
    if var in _PROVIDER_BY_VAR:
        return _PROVIDER_BY_VAR[var]
    lowered = var.lower()
    for known, provider in _PROVIDER_BY_VAR.items():
        stem = known.split("_")[0].lower()
        if stem and stem in lowered and len(stem) > 3:  # e.g. OPENAI_KEY -> openai
            return provider
    return None


def extract_secrets(repo: str | Path) -> SecretReport:
    """Statically extract required secrets, egress hosts, and providers for a repo."""
    secrets = scan_env_vars(repo)
    hosts = sorted(iter_repo_hosts(repo))
    providers: set[str] = set()
    for var in secrets:
        provider = _provider_for(var)
        if provider:
            providers.add(provider)
    for host in hosts:
        for needle, provider in _PROVIDER_BY_HOST.items():
            if needle in host:
                providers.add(provider)
    paid = sorted(p for p in providers if p not in FREE_TIER_PROVIDERS)
    return SecretReport(
        required_secrets=secrets,
        allowed_hosts=hosts,
        providers=sorted(providers),
        paid_providers=paid,
    )
