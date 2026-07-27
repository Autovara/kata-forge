"""Classify a validator repo's dependencies as free / gpu / paid-api / gated-data.

This is the go/no-go gate for onboarding a subnet: can it be validated without money (paid
inference/scrape keys), a GPU, or gated data access. We parse the declared deps
(``requirements.txt`` + ``pyproject.toml``) and, as a backstop, scan imports for deps that are
used but never declared. Each dep maps to exactly one bucket via a static table; unknown deps
default to *free* but are surfaced under ``unclassified`` so a human eyeballs them rather than
trusting a silent "free". The rollup verdict is the honest headline: NEEDS-KEYS > NEEDS-GPU > FREE.
"""

from __future__ import annotations

import re
import sys
import tomllib
from dataclasses import dataclass
from pathlib import Path

# Exact distribution/import names that force a bucket. Normalized (lowercase, "_"->"-", no extras).
_GPU = {
    "torch", "torchvision", "torchaudio", "tensorflow", "tensorflow-gpu", "jax", "jaxlib",
    "vllm", "xformers", "flash-attn", "bitsandbytes", "triton", "cupy", "onnxruntime-gpu",
    "deepspeed", "accelerate",
}
_PAID_API = {
    "openai", "anthropic", "cohere", "mistralai", "replicate", "together", "groq",
    "apify-client", "scrapingdog", "serpapi", "google-search-results", "boto3", "botocore",
    "tavily-python", "firecrawl-py",
}
_GATED_DATA = {"datasets", "huggingface-hub", "kaggle"}
# Common deps known to run for free (no key, no GPU). Everything not here and not in a paid/gpu
# table lands in ``unclassified`` for a human to eyeball -- we never silently call an unknown free.
_FREE_KNOWN = {
    "numpy", "scipy", "pandas", "scikit-learn", "requests", "httpx", "aiohttp", "urllib3",
    "pydantic", "pydantic-settings", "python-dotenv", "pyyaml", "toml", "click", "rich", "tqdm",
    "fastapi", "uvicorn", "starlette", "flask", "jinja2", "beautifulsoup4", "lxml", "pillow",
    "matplotlib", "seaborn", "networkx", "sqlalchemy", "redis", "pymongo", "websockets",
    "bittensor", "substrate-interface", "scalecodec", "wandb", "loguru", "typer", "orjson",
    "python-dateutil", "pytz", "setuptools", "wheel", "packaging", "cryptography", "pynacl",
    "pycryptodome", "six", "certifi", "charset-normalizer", "idna", "attrs", "protobuf",
}
# Prefix families -> bucket (matched after exact hits).
_PREFIX_BUCKETS = (
    ("nvidia-", "gpu"),
    ("cuda-", "gpu"),
    ("google-cloud-", "paid-api"),
    ("azure-", "paid-api"),
)
# import name -> distribution name, for the cases where they differ and the bucket matters.
_IMPORT_ALIASES = {
    "sklearn": "scikit-learn", "cv2": "opencv-python", "PIL": "pillow", "bs4": "beautifulsoup4",
    "apify_client": "apify-client", "huggingface_hub": "huggingface-hub", "yaml": "pyyaml",
    "dotenv": "python-dotenv", "Crypto": "pycryptodome", "dateutil": "python-dateutil",
}
# The complete stdlib module set (3.10+) -- skipped in the import backstop, plus __future__.
_STDLIB = set(sys.stdlib_module_names) | {"__future__"}


@dataclass(frozen=True)
class DepReport:
    """A free-vs-paid dependency verdict for a repo."""

    verdict: str  # FREE | NEEDS-KEYS | NEEDS-GPU
    free: list[str]
    gpu: list[str]
    paid_api: list[str]
    gated_data: list[str]
    unclassified: list[str]  # unknown deps (counted as free for the verdict, but flagged)
    sources: list[str]  # repo-relative files parsed


def _normalize(name: str) -> str:
    name = name.strip().lower().replace("_", "-")
    name = re.sub(r"\[.*?\]", "", name)  # drop extras: foo[bar] -> foo
    return name


def _strip_spec(line: str) -> str:
    # "numpy>=1.24 ; python_version>'3.8'  # comment" -> "numpy"
    line = line.split("#", 1)[0].split(";", 1)[0].strip()
    return re.split(r"[<>=!~ \[]", line, maxsplit=1)[0].strip()


def parse_requirements(text: str) -> list[str]:
    """Dep names from a ``requirements.txt`` body (ignores -r/-e/-c/URLs/blank/comments)."""
    out: list[str] = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith(("#", "-")):
            continue
        if "://" in line or line.startswith("git+"):
            continue
        name = _strip_spec(line)
        if name:
            out.append(name)
    return out


def parse_pyproject(text: str) -> list[str]:
    """Dep names from ``pyproject.toml`` (PEP 621 + optional-deps + poetry fallback)."""
    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError:
        return []
    names: list[str] = []
    project = data.get("project", {})
    for dep in project.get("dependencies", []) or []:
        names.append(_strip_spec(dep))
    for group in (project.get("optional-dependencies", {}) or {}).values():
        for dep in group or []:
            names.append(_strip_spec(dep))
    poetry = data.get("tool", {}).get("poetry", {}).get("dependencies", {}) or {}
    for name in poetry:
        if name.lower() != "python":
            names.append(name)
    return [n for n in names if n]


def scan_imports(repo: Path) -> list[str]:
    """Top-level third-party import names across the repo (backstop for undeclared deps)."""
    pattern = re.compile(r"^\s*(?:import|from)\s+([a-zA-Z0-9_]+)", re.MULTILINE)
    found: set[str] = set()
    for py in repo.rglob("*.py"):
        if any(part in {".venv", "venv", "node_modules", ".git", "build", "dist"} for part in py.parts):
            continue
        try:
            text = py.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        for match in pattern.findall(text):
            if match not in _STDLIB:
                found.add(match)
    return sorted(found)


def bucket_dep(name: str) -> str:
    """Map one dep (distribution or import name) to free/gpu/paid-api/gated-data/unknown."""
    norm = _normalize(name)
    norm = _normalize(_IMPORT_ALIASES.get(name, _IMPORT_ALIASES.get(norm, norm)))
    if norm in _GPU:
        return "gpu"
    if norm in _PAID_API:
        return "paid-api"
    if norm in _GATED_DATA:
        return "gated-data"
    for prefix, bucket in _PREFIX_BUCKETS:
        if norm.startswith(prefix):
            return bucket
    if norm in _FREE_KNOWN:
        return "free"
    return "unknown"


def _looks_local(name: str, repo: Path) -> bool:
    # An import that resolves to a package/module inside the repo isn't a dependency.
    stem = _normalize(name).replace("-", "_")
    return (repo / stem).is_dir() or (repo / f"{stem}.py").is_file()


def classify_repo(path: str | Path) -> DepReport:
    """Parse a repo's deps and return a free-vs-paid :class:`DepReport`."""
    repo = Path(path).expanduser()
    declared: list[str] = []
    sources: list[str] = []
    for req in sorted(repo.rglob("requirements*.txt")):
        if any(p in {".venv", "venv", ".git"} for p in req.parts):
            continue
        declared += parse_requirements(req.read_text(encoding="utf-8", errors="ignore"))
        sources.append(str(req.relative_to(repo)))
    pyproject = repo / "pyproject.toml"
    if pyproject.is_file():
        declared += parse_pyproject(pyproject.read_text(encoding="utf-8", errors="ignore"))
        sources.append("pyproject.toml")

    declared_norm = {_normalize(d) for d in declared}
    imported = [
        name for name in scan_imports(repo)
        if _normalize(name) not in declared_norm
        and _IMPORT_ALIASES.get(name, "") not in declared_norm
        and not _looks_local(name, repo)
    ]

    buckets: dict[str, list[str]] = {"free": [], "gpu": [], "paid-api": [], "gated-data": [], "unknown": []}
    seen: set[str] = set()
    for name in [*declared, *imported]:
        key = _normalize(name)
        if key in seen:
            continue
        seen.add(key)
        bucket = bucket_dep(name)
        buckets["unknown" if bucket == "unknown" else bucket].append(key)

    if buckets["paid-api"] or buckets["gated-data"]:
        verdict = "NEEDS-KEYS"
    elif buckets["gpu"]:
        verdict = "NEEDS-GPU"
    else:
        verdict = "FREE"
    return DepReport(
        verdict=verdict,
        free=sorted(set(buckets["free"])),
        gpu=sorted(buckets["gpu"]),
        paid_api=sorted(buckets["paid-api"]),
        gated_data=sorted(buckets["gated-data"]),
        unclassified=sorted(buckets["unknown"]),
        sources=sources,
    )
