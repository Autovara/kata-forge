"""M3.5 -- prove the whole extract pipeline reproduces the hand-done Poker44 feasibility analysis.

This is an offline, known-good regression lock: resolve -> classify -> anchors -> report/scaffold
over the already-cloned Poker44 repo must reproduce every finding in ``sn126-feasibility.md``
(scorer = pure ``reward``, deps = FREE, benchmark = the public no-auth API, miner = a Synapse).
If any heuristic drifts, this fails.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from kata_forge.anchors import extract_anchors
from kata_forge.deps import classify_repo
from kata_forge.report import write_extract
from kata_forge.resolver import resolve_repo
from kata_forge.spec import validate_spec

POKER44 = Path("/tmp/poker44-research")
pytestmark = pytest.mark.skipif(not POKER44.exists(), reason="poker44 clone not present")


def test_pipeline_reproduces_poker44_feasibility(tmp_path) -> None:
    # 1. resolve + pin (offline, local path)
    resolved = resolve_repo(repo=str(POKER44))
    assert resolved.commit == "2ceac436e896b8c9a3b4991ceb6d0644c8ad8d9a"

    # 2. deps verdict == FREE, no keys/gpu (hand analysis: "Free to validate? YES")
    deps = classify_repo(resolved.path)
    assert deps.verdict == "FREE"
    assert not (deps.paid_api or deps.gpu or deps.gated_data)
    assert {"numpy", "scikit-learn", "pandas", "requests", "pydantic", "bittensor"}.issubset(
        set(deps.free)
    )

    # 3. anchors == the three the human found by hand
    anchors = extract_anchors(resolved.path)
    assert (anchors.scorer.file, anchors.scorer.symbol) == ("poker44/score/scoring.py", "reward")
    assert "float" in anchors.scorer.detail  # pure scalar-returning scorer
    assert anchors.benchmark.symbol == "api.poker44.net"  # public no-auth benchmark API
    assert (anchors.miner.file, anchors.miner.symbol) == (
        "poker44/validator/synapse.py",
        "DetectionSynapse",
    )
    assert anchors.scorer.confidence == "high"

    # 4. report + anchored scaffold, and the scaffold's plugin.py stays valid + carries the anchors
    spec = validate_spec(subnet_number=126, pack="sn126__poker44", evaluator_id="sn126_poker44")
    outputs = write_extract(
        out_dir=tmp_path, subnet=126, resolved=resolved, deps=deps, anchors=anchors, spec=spec
    )
    report = outputs.analysis_path.read_text(encoding="utf-8")
    assert "FREE" in report and "poker44/score/scoring.py:94" in report

    plugin = next(p for p in outputs.scaffold_paths if p.name == "plugin.py")
    body = plugin.read_text(encoding="utf-8")
    for needle in ("poker44/score/scoring.py:94", "DetectionSynapse", "api.poker44.net"):
        assert needle in body
    compile(body, "plugin.py", "exec")
