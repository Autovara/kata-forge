"""Locate the code->contract anchors a plugin author needs: scorer, benchmark source, miner.

Onboarding a subnet is mostly *finding three things* in the validator repo: the **scorer**
(the reward/score function), the **task/benchmark source** (a dataset dir or an HTTP endpoint),
and the **miner/agent contract** (a ``bt.Synapse`` subclass or an ``agent_main``/``forward``).
This module finds them with a static AST walk plus ranking heuristics -- no execution -- and
returns file+symbol anchors with a snippet, so the M3.4 report/scaffold can point each TODO at the
exact source. Ranking is best-effort: it returns ranked candidates too, so a human can override.
"""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field
from pathlib import Path

_SKIP_DIRS = {".venv", "venv", ".git", "build", "dist", "node_modules", "tests", "test", "__pycache__"}
_URL = re.compile(r"https?://[^\s\"'<>)\]]+")
# URL hosts that are never a benchmark source (packaging, docs, schemas, local).
_URL_NOISE = ("github.com", "githubusercontent", "pypi.org", "readthedocs", "schemas.",
              "json-schema.org", "w3.org", "localhost", "127.0.0.1", "example.com",
              "opensource.org", "apache.org", "gravatar.com", "sentry.io")
_SCORER_NAMES = ("reward", "score", "evaluate", "compute_reward", "compute_score", "get_reward")
_MINER_FUNCS = ("agent_main", "forward", "run_agent", "infer", "predict", "generate")
_SCORER_ARGS = ("pred", "true", "label", "target", "y_", "gold", "expected", "actual")
# Path segments that mark tutorial/example code -- demoted so canonical source wins ties.
_DEMOTE_DIRS = {"docs", "doc", "examples", "example", "tutorial", "tutorials", "samples", "sample"}


@dataclass(frozen=True)
class Anchor:
    """A located source symbol an author should map into the plugin contract."""

    kind: str  # scorer | benchmark | miner
    file: str  # repo-relative path
    symbol: str  # function/class name, or a URL host
    lineno: int
    detail: str  # signature / base classes / url
    snippet: str  # a couple of source lines at the anchor
    confidence: str  # high | medium | low


@dataclass
class AnchorReport:
    """The best anchor per kind, plus all ranked candidates for override."""

    scorer: Anchor | None = None
    benchmark: Anchor | None = None
    miner: Anchor | None = None
    candidates: dict[str, list[Anchor]] = field(default_factory=dict)


def _iter_py(repo: Path):
    for py in sorted(repo.rglob("*.py")):
        if any(part in _SKIP_DIRS for part in py.relative_to(repo).parts):
            continue
        yield py


def iter_repo_hosts(repo: str | Path) -> dict[str, int]:
    """External hosts referenced in the repo (noise hosts filtered), as host -> reference count."""
    repo = Path(repo).expanduser()
    counts: dict[str, int] = {}
    for py in _iter_py(repo):
        text = py.read_text(encoding="utf-8", errors="ignore")
        for match in _URL.finditer(text):
            host = re.sub(r"^https?://", "", match.group(0)).split("/")[0].rstrip(".,)")
            if host and not any(noise in host for noise in _URL_NOISE):
                counts[host] = counts.get(host, 0) + 1
    return counts


def _snippet(lines: list[str], lineno: int, n: int = 2) -> str:
    start = max(0, lineno - 1)
    return "\n".join(lines[start : start + n]).strip()


def _returns(node: ast.AST) -> str:
    ret = getattr(node, "returns", None)
    return ast.unparse(ret) if ret is not None else ""


def _arg_names(node: ast.FunctionDef | ast.AsyncFunctionDef) -> list[str]:
    return [a.arg for a in node.args.args]


def _confidence(points: int) -> str:
    return "high" if points >= 4 else "medium" if points >= 2 else "low"


def _path_penalty(rel: str) -> int:
    return 3 if any(part in _DEMOTE_DIRS for part in Path(rel).parts) else 0


def _score_scorer(node, rel: str) -> tuple[int, str] | None:
    name = node.name
    lname = name.lower()
    if not any(key in lname for key in _SCORER_NAMES):
        return None
    if any(bad in lname for bad in ("manifest", "compliance", "suspicion", "config")):
        return None  # named-like-a-scorer decoys in validator plumbing
    points = 0
    if lname == "reward":
        points += 4
    elif lname == "score":
        points += 3
    elif "reward" in lname or "score" in lname:
        points += 2
    else:
        points += 1  # evaluate*
    ret = _returns(node).lower()
    if "float" in ret:
        points += 2
    if "tuple" in ret:
        points += 1
    if "dict" in ret:
        points += 1
    if any(hint in arg.lower() for arg in _arg_names(node) for hint in _SCORER_ARGS):
        points += 1
    return points, f"def {name}({', '.join(_arg_names(node))}) -> {_returns(node) or '?'}"


def _score_miner_class(node: ast.ClassDef, rel: str) -> tuple[int, str] | None:
    bases = [ast.unparse(b) for b in node.bases]
    if any(b.split(".")[-1].endswith("Synapse") for b in bases):
        return 5, f"class {node.name}({', '.join(bases)})"
    return None


def _score_miner_func(node, rel: str) -> tuple[int, str] | None:
    lname = node.name.lower()
    if lname not in _MINER_FUNCS:
        return None
    points = 4 if lname == "agent_main" else 2 if lname == "forward" else 1
    return points, f"def {node.name}({', '.join(_arg_names(node))})"


def _collect(repo: Path):
    scorers: list[tuple[int, Anchor]] = []
    miners: list[tuple[int, Anchor]] = []
    urls: dict[str, tuple[int, Anchor]] = {}  # host -> (count, first anchor)
    for py in _iter_py(repo):
        rel = str(py.relative_to(repo))
        text = py.read_text(encoding="utf-8", errors="ignore")
        lines = text.splitlines()
        for match in _URL.finditer(text):
            url = match.group(0).rstrip(".,)")
            host = re.sub(r"^https?://", "", url).split("/")[0]
            if any(noise in host for noise in _URL_NOISE):
                continue
            lineno = text.count("\n", 0, match.start()) + 1
            count, existing = urls.get(host, (0, None))
            anchor = existing or Anchor("benchmark", rel, host, lineno, url, _snippet(lines, lineno), "medium")
            urls[host] = (count + 1, anchor)
        try:
            tree = ast.parse(text)
        except SyntaxError:
            continue
        for node in ast.walk(tree):
            penalty = _path_penalty(rel)
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                scored = _score_scorer(node, rel)
                if scored:
                    pts, detail = scored[0] - penalty, scored[1]
                    scorers.append((pts, Anchor("scorer", rel, node.name, node.lineno, detail, _snippet(lines, node.lineno), _confidence(pts))))
                mined = _score_miner_func(node, rel)
                if mined:
                    pts, detail = mined[0] - penalty, mined[1]
                    miners.append((pts, Anchor("miner", rel, node.name, node.lineno, detail, _snippet(lines, node.lineno), _confidence(pts))))
            elif isinstance(node, ast.ClassDef):
                mined = _score_miner_class(node, rel)
                if mined:
                    pts, detail = mined[0] - penalty, mined[1]
                    miners.append((pts, Anchor("miner", rel, node.name, node.lineno, detail, _snippet(lines, node.lineno), _confidence(pts))))
    return scorers, miners, urls


def extract_anchors(path: str | Path) -> AnchorReport:
    """Statically locate the scorer, benchmark source, and miner contract in a repo."""
    repo = Path(path).expanduser()
    scorers, miners, urls = _collect(repo)

    scorers.sort(key=lambda x: (-x[0], x[1].file, x[1].lineno))
    miners.sort(key=lambda x: (-x[0], x[1].file, x[1].lineno))
    # A benchmark host referenced more often, or one that looks like an api/data endpoint, ranks up.
    bench = sorted(
        urls.values(),
        key=lambda cv: (-(cv[0] + (2 if re.search(r"\b(api|benchmark|dataset|data)\b", cv[1].symbol) else 0)), cv[1].file),
    )
    bench_anchors = [c[1] for c in bench]
    top_bench = None
    if bench_anchors:
        best = bench_anchors[0]
        strong = bool(re.search(r"\b(api|benchmark|dataset|data)\b", best.symbol))
        top_bench = Anchor(**{**best.__dict__, "confidence": "high" if strong else "medium"})

    return AnchorReport(
        scorer=scorers[0][1] if scorers else None,
        benchmark=top_bench,
        miner=miners[0][1] if miners else None,
        candidates={
            "scorer": [a for _, a in scorers],
            "benchmark": bench_anchors,
            "miner": [a for _, a in miners],
        },
    )
