from __future__ import annotations

import ast

import pytest

from kata_forge.cli import main
from kata_forge.generator import GeneratorError, generate, render
from kata_forge.spec import validate_spec

SPEC = validate_spec(subnet_number=126, pack="sn126__poker44", evaluator_id="sn126_poker44")

EXPECTED_FILES = {
    "pyproject.toml",
    "kata_sn126/__init__.py",
    "kata_sn126/models.py",
    "kata_sn126/plugin.py",
    "tests/test_plugin.py",
    "README.md",
    ".gitignore",
    "deploy/lane-config.md",
}


def test_render_substitutes_and_rejects_unknown() -> None:
    assert render("hi {{SLUG}} sn{{N}}", {"SLUG": "poker44", "N": "126"}) == "hi poker44 sn126"
    with pytest.raises(GeneratorError):
        render("{{NOPE}}", {})


def test_generate_writes_the_full_skeleton(tmp_path) -> None:
    written = generate(SPEC, tmp_path)
    target = tmp_path / "kata-sn126"
    assert {p.relative_to(target).as_posix() for p in written} == EXPECTED_FILES


def test_generated_files_have_no_placeholders_and_valid_python(tmp_path) -> None:
    generate(SPEC, tmp_path)
    for path in (tmp_path / "kata-sn126").rglob("*"):
        if not path.is_file():
            continue
        text = path.read_text(encoding="utf-8")
        # No `{{VAR}}` placeholder left ( `}}` alone is legit, e.g. JSON `{}` closing a table).
        assert "{{" not in text, f"unsubstituted placeholder in {path.name}"
        if path.suffix == ".py":
            ast.parse(text)  # generated Python parses


def test_generated_identity_and_stubs(tmp_path) -> None:
    generate(SPEC, tmp_path)
    root = tmp_path / "kata-sn126"
    plugin = (root / "kata_sn126" / "plugin.py").read_text()
    assert 'EVALUATOR_ID = "sn126_poker44"' in plugin
    assert "class Poker44Plugin(SubnetPlugin):" in plugin
    assert plugin.count("NotImplementedError") >= 4  # the hard methods are stubs
    init = (root / "kata_sn126" / "__init__.py").read_text()
    assert "POKER44_PLUGIN = Poker44Plugin()" in init
    pyproject = (root / "pyproject.toml").read_text()
    assert 'sn126 = "kata_sn126:POKER44_PLUGIN"' in pyproject


def test_generation_is_idempotent_with_force(tmp_path) -> None:
    generate(SPEC, tmp_path)
    with pytest.raises(GeneratorError):
        generate(SPEC, tmp_path)  # non-empty target without force
    generate(SPEC, tmp_path, force=True)  # force overwrites cleanly


def test_cli_new_scaffolds_to_disk(tmp_path) -> None:
    rc = main(
        ["new", "--subnet", "126", "--pack", "sn126__poker44",
         "--evaluator", "sn126_poker44", "--out", str(tmp_path)]
    )
    assert rc == 0
    assert (tmp_path / "kata-sn126" / "kata_sn126" / "plugin.py").is_file()
