"""Render the templates for a spec and write a ``kata-sn<N>`` skeleton.

Placeholders are ``{{UPPER}}`` tokens; a missing one is an error (catches template typos)
rather than a silent gap. Generation writes into ``<out>/<repo_name>/`` and refuses to
clobber a non-empty target without ``force``. It never touches any other repo or git.
"""

from __future__ import annotations

import re
from pathlib import Path

from kata_forge.spec import SubnetSpec
from kata_forge.templates import TEMPLATES

_PLACEHOLDER = re.compile(r"\{\{(\w+)\}\}")


class GeneratorError(Exception):
    """Scaffolding could not proceed (unknown placeholder or a non-empty target)."""


def template_vars(spec: SubnetSpec) -> dict[str, str]:
    """Every ``{{VAR}}`` the templates may reference, derived from the spec."""
    return {
        "N": str(spec.subnet_number),
        "PACKAGE": spec.package,
        "REPO": spec.repo_name,
        "BASE": spec.base_name,
        "CLASS": spec.class_name,
        "SINGLETON": spec.singleton,
        "EVALUATOR": spec.evaluator_id,
        "PACK": spec.pack,
        "MODE": spec.mode,
        "SLUG": spec.slug,
        "DISPLAY": spec.display_title,
    }


def render(template: str, variables: dict[str, str]) -> str:
    """Substitute every ``{{VAR}}`` token; raise on an unknown placeholder."""

    def _replace(match: re.Match[str]) -> str:
        key = match.group(1)
        if key not in variables:
            raise GeneratorError(f"unknown template placeholder {{{{{key}}}}}")
        return variables[key]

    return _PLACEHOLDER.sub(_replace, template)


def generate(spec: SubnetSpec, out_dir: str | Path, *, force: bool = False) -> list[Path]:
    """Render the skeleton for ``spec`` into ``<out_dir>/<repo_name>/``; return written paths."""
    variables = template_vars(spec)
    target = Path(out_dir).expanduser().resolve() / spec.repo_name
    if target.exists() and any(target.iterdir()) and not force:
        raise GeneratorError(f"{target} already exists and is not empty; pass force=True to overwrite")
    written: list[Path] = []
    for path_template, content_template in TEMPLATES.items():
        path = target / render(path_template, variables)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(render(content_template, variables), encoding="utf-8")
        written.append(path)
    return sorted(written)
