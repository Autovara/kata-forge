from __future__ import annotations

from pathlib import Path

import pytest

from kata_forge.deps import (
    bucket_dep,
    classify_repo,
    parse_pyproject,
    parse_requirements,
    scan_imports,
)

POKER44 = Path("/tmp/poker44-research")


def test_parse_requirements_strips_specs_and_noise() -> None:
    text = "\n".join(
        [
            "numpy>=1.24",
            "scikit-learn>=1.3  # scorer",
            "requests>=2.31 ; python_version>'3.8'",
            "",
            "# a comment",
            "-r base.txt",
            "-e .",
            "git+https://example.com/x.git",
            "foo[bar]==1.0",
        ]
    )
    assert parse_requirements(text) == ["numpy", "scikit-learn", "requests", "foo"]


def test_parse_pyproject_project_and_optional_and_poetry() -> None:
    text = """
[project]
dependencies = ["numpy>=1.24", "openai>=1.0"]
[project.optional-dependencies]
dev = ["pytest>=8"]
[tool.poetry.dependencies]
python = "^3.11"
anthropic = "*"
"""
    assert set(parse_pyproject(text)) == {"numpy", "openai", "pytest", "anthropic"}


def test_bucket_dep_tables_and_aliases() -> None:
    assert bucket_dep("torch") == "gpu"
    assert bucket_dep("openai") == "paid-api"
    assert bucket_dep("datasets") == "gated-data"
    assert bucket_dep("nvidia-cublas-cu12") == "gpu"
    assert bucket_dep("google-cloud-storage") == "paid-api"
    assert bucket_dep("sklearn") == "free"  # import alias -> scikit-learn
    assert bucket_dep("numpy") == "free"
    assert bucket_dep("some-obscure-lib") == "unknown"


def test_classify_synthetic_paid_repo(tmp_path) -> None:
    (tmp_path / "requirements.txt").write_text("numpy\nopenai>=1.0\n", encoding="utf-8")
    report = classify_repo(tmp_path)
    assert report.verdict == "NEEDS-KEYS"
    assert "openai" in report.paid_api
    assert "numpy" in report.free


def test_classify_synthetic_gpu_repo(tmp_path) -> None:
    (tmp_path / "requirements.txt").write_text("torch\nnumpy\n", encoding="utf-8")
    report = classify_repo(tmp_path)
    assert report.verdict == "NEEDS-GPU"
    assert "torch" in report.gpu


def test_classify_pyproject_only(tmp_path) -> None:
    (tmp_path / "pyproject.toml").write_text(
        '[project]\ndependencies = ["numpy>=1.24", "scikit-learn"]\n', encoding="utf-8"
    )
    report = classify_repo(tmp_path)
    assert report.verdict == "FREE"
    assert report.sources == ["pyproject.toml"]


def test_import_backstop_catches_undeclared_paid(tmp_path) -> None:
    (tmp_path / "requirements.txt").write_text("numpy\n", encoding="utf-8")
    (tmp_path / "agent.py").write_text("import anthropic\nimport numpy\n", encoding="utf-8")
    report = classify_repo(tmp_path)
    assert report.verdict == "NEEDS-KEYS"  # anthropic found via import scan
    assert "anthropic" in report.paid_api


def test_unknown_dep_is_flagged_not_silently_free(tmp_path) -> None:
    (tmp_path / "requirements.txt").write_text("numpy\nsome-obscure-lib\n", encoding="utf-8")
    report = classify_repo(tmp_path)
    assert report.verdict == "FREE"  # unknown doesn't force NEEDS-KEYS
    assert "some-obscure-lib" in report.unclassified
    assert "some-obscure-lib" not in report.free


def test_scan_imports_skips_stdlib_and_future(tmp_path) -> None:
    (tmp_path / "m.py").write_text(
        "from __future__ import annotations\nimport os\nimport json\nimport requests\n"
        "from anthropic import Anthropic\n",
        encoding="utf-8",
    )
    found = scan_imports(tmp_path)
    assert "requests" in found and "anthropic" in found
    assert "os" not in found and "json" not in found and "__future__" not in found


def test_local_package_import_not_counted_as_dep(tmp_path) -> None:
    (tmp_path / "requirements.txt").write_text("numpy\n", encoding="utf-8")
    (tmp_path / "mypkg").mkdir()
    (tmp_path / "mypkg" / "__init__.py").write_text("", encoding="utf-8")
    (tmp_path / "app.py").write_text("import mypkg\nimport numpy\n", encoding="utf-8")
    report = classify_repo(tmp_path)
    assert "mypkg" not in report.unclassified


@pytest.mark.skipif(not POKER44.exists(), reason="poker44 clone not present")
def test_poker44_classifies_free() -> None:
    report = classify_repo(POKER44)
    assert report.verdict == "FREE"
    assert not report.paid_api
    assert not report.gpu
    assert not report.gated_data
    assert {"numpy", "scikit-learn"}.issubset(set(report.free))
