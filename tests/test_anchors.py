from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

from kata_forge.anchors import extract_anchors

POKER44 = Path("/tmp/poker44-research")


def _write(repo: Path, rel: str, body: str) -> None:
    path = repo / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(textwrap.dedent(body), encoding="utf-8")


def test_finds_scorer_benchmark_miner_synthetic(tmp_path) -> None:
    _write(
        tmp_path,
        "sn/score.py",
        """
        import numpy as np
        def reward(y_pred: np.ndarray, y_true: np.ndarray) -> tuple[float, dict]:
            return 1.0, {}
        """,
    )
    _write(
        tmp_path,
        "sn/net.py",
        '''
        BASE = "https://api.example-subnet.net/benchmark"
        ''',
    )
    _write(
        tmp_path,
        "sn/synapse.py",
        """
        import bittensor as bt
        class DetectionSynapse(bt.Synapse):
            pass
        """,
    )
    report = extract_anchors(tmp_path)
    assert report.scorer and report.scorer.symbol == "reward"
    assert report.scorer.confidence == "high"
    assert report.benchmark and "example-subnet.net" in report.benchmark.symbol
    assert report.miner and report.miner.symbol == "DetectionSynapse"


def test_scorer_beats_decoy_and_ranks_reward_first(tmp_path) -> None:
    _write(
        tmp_path,
        "a.py",
        """
        def evaluate_manifest_compliance(m) -> dict:
            return {}
        def reward(y_pred, y_true) -> tuple[float, dict]:
            return 0.0, {}
        """,
    )
    report = extract_anchors(tmp_path)
    assert report.scorer.symbol == "reward"  # decoy dropped, reward wins
    names = [a.symbol for a in report.candidates["scorer"]]
    assert "evaluate_manifest_compliance" not in names


def test_miner_prefers_synapse_over_forward(tmp_path) -> None:
    _write(tmp_path, "m.py", "def forward(self, syn): ...")
    _write(tmp_path, "s.py", "import bittensor as bt\nclass MySynapse(bt.Synapse): pass\n")
    report = extract_anchors(tmp_path)
    assert report.miner.symbol == "MySynapse"


def test_agent_main_is_top_miner_when_no_synapse(tmp_path) -> None:
    _write(tmp_path, "agent.py", "def forward(x): ...\ndef agent_main(chunks): ...")
    report = extract_anchors(tmp_path)
    assert report.miner.symbol == "agent_main"


def test_canonical_source_beats_docs_tutorial(tmp_path) -> None:
    _write(tmp_path, "docs/tutorial/protocol.py", "import bittensor as bt\nclass DocSynapse(bt.Synapse): pass\n")
    _write(tmp_path, "pkg/protocol.py", "import bittensor as bt\nclass RealSynapse(bt.Synapse): pass\n")
    report = extract_anchors(tmp_path)
    assert report.miner.symbol == "RealSynapse"  # docs/ demoted below real source


def test_noise_urls_and_tests_dir_excluded(tmp_path) -> None:
    _write(tmp_path, "u.py", 'X = "https://github.com/org/repo"\nY = "https://pypi.org/simple"')
    _write(tmp_path, "tests/test_x.py", "def reward(a, b) -> float: return 1.0")
    report = extract_anchors(tmp_path)
    assert report.benchmark is None  # only noise hosts
    assert report.scorer is None  # scorer only defined under tests/ -> skipped


@pytest.mark.skipif(not POKER44.exists(), reason="poker44 clone not present")
def test_poker44_anchors_match_hand_analysis() -> None:
    report = extract_anchors(POKER44)
    assert report.scorer.file == "poker44/score/scoring.py"
    assert report.scorer.symbol == "reward"
    assert report.benchmark.symbol == "api.poker44.net"
    assert report.miner.symbol == "DetectionSynapse"
    assert report.miner.file == "poker44/validator/synapse.py"
