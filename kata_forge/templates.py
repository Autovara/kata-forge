"""The parametrized ``kata-sn<N>`` skeleton, templatized from the hand-built ``kata-sn126``.

Placeholders are ``{{UPPER}}`` tokens (see ``generator.template_vars``); every other brace --
TOML tables, dataclass calls -- is literal and passes through untouched. File *paths* are
templated too (e.g. ``{{PACKAGE}}/plugin.py``). The generated boilerplate is complete; the four
subnet-specific methods are documented stubs for a human (or M3) to fill.
"""

from __future__ import annotations

_PYPROJECT = '''\
[project]
name = "{{REPO}}"
version = "0.1.0"
description = "SN{{N}} ({{DISPLAY}}) subnet plugin for the Kata competition platform."
requires-python = ">=3.12"
dependencies = [
  "kata",
  # TODO: add this subnet's scorer/runtime deps (e.g. numpy, scikit-learn).
]

[project.optional-dependencies]
dev = ["pytest>=8.0", "ruff>=0.6"]

# Discovered by the Kata platform via the kata.subnets entry-point group.
[project.entry-points."kata.subnets"]
sn{{N}} = "{{PACKAGE}}:{{SINGLETON}}"

[build-system]
requires = ["hatchling"]
build-backend = "hatchling.build"

[tool.hatch.build.targets.wheel]
packages = ["{{PACKAGE}}"]

# NOTE: deliberately no [tool.uv.sources] pinning `kata` to "../kata". That only resolves in a dev
# checkout laid out beside the core, and it silently breaks everywhere the plugin is actually used:
# inside a release bundle, inside the Verify compartment, and inside the candidate runtime, where
# `kata` comes from the verified base wheel rather than a sibling directory. For local development,
# install the core into your venv (`uv pip install -e ../kata`) instead of pinning it here.

[tool.ruff]
line-length = 100
'''

_INIT = '''\
"""The SN{{N}} ({{DISPLAY}}) subnet plugin.

Importing this package registers the plugin with the core registry. Fill the four
subnet-specific methods in plugin.py; see kata-sn126 for a worked reference.
"""

from __future__ import annotations

from kata.plugins.registry import register_plugin

from .models import {{BASE}}Problems, {{BASE}}RawRun
from .plugin import {{CLASS}}

#: The singleton plugin instance the core resolves by evaluator id.
{{SINGLETON}} = {{CLASS}}()

register_plugin({{SINGLETON}})

__all__ = [
    "{{SINGLETON}}",
    "{{CLASS}}",
    "{{BASE}}Problems",
    "{{BASE}}RawRun",
]
'''

_MODELS = '''\
"""Shared value types for the {{DISPLAY}} plugin (kept separate to avoid import cycles).

TODO: replace the placeholder fields with this subnet's real shapes (task inputs + labels for
Problems; the agent's raw output for RawRun). See kata-sn126/kata_sn126/models.py.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class {{BASE}}Problems:
    """This challenge's task set + a deterministic ``identity`` for benchmark caching."""

    problems: tuple[Any, ...] = ()
    identity: str = ""
    config: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class {{BASE}}RawRun:
    """A candidate agent's raw run output from run_candidate."""

    output: tuple[Any, ...] = ()
    coverage: float = 0.0
'''

_PLUGIN = '''\
"""SN{{N}} / {{DISPLAY}} subnet plugin.

Scaffolded by kata-forge. Everything below is complete EXCEPT the four subnet-specific methods
(sample_problems + benchmark_identity, run_candidate, score, compare + beats_king), which raise
NotImplementedError until you fill them. See kata-sn126 for a worked reference and
kata-sn126-build-plan.md for the sub-step recipe.
"""

from __future__ import annotations

from typing import Any

from kata.plugins.contract import (
    EnvSpec,
    RunContext,
    ScoreCard,
    ScoringProfile,
    SubnetPlugin,
)

from {{PACKAGE}}.models import {{BASE}}Problems, {{BASE}}RawRun

EVALUATOR_ID = "{{EVALUATOR}}"
LANE_PACK = "{{PACK}}"
VALIDATOR_IDENTITY = "{{SLUG}}-v1"

#: Methods still to be written for this subnet. The build reads this list rather than guessing, and
#: the trusted installer REFUSES a bundle whose list is non-empty -- an honest UNRESOLVED build is
#: reviewable, but it must never become a half-working deployment. Delete a name once its body and
#: its tests are real.
UNRESOLVED_METHODS = (
    "sample_problems",
    "benchmark_identity",
    "run_candidate",
    "score",
)


class {{CLASS}}(SubnetPlugin):
    """SN{{N}} {{DISPLAY}} plugin."""

    evaluator_id = EVALUATOR_ID
    pack = LANE_PACK
    mode = "{{MODE}}"
    # TODO: DETERMINISTIC if scores are reproducible on a fixed benchmark; NOISY if they drift
    # (e.g. LLM-judged) so each contender is re-scored fresh. NOISY is the safe default.
    scoring_profile = ScoringProfile.NOISY
    validator_identity = VALIDATOR_IDENTITY

    def environment_spec(self) -> EnvSpec:
        # TODO: set the sandbox/network/secret requirements. Default: fully sealed (no network,
        # no secrets) for a self-contained agent. Use network="relay_only" + required_secrets
        # for a subnet whose agents need an inference gateway or a data-provider key.
        return EnvSpec(network="none", allowed_hosts=(), required_secrets=(), execution="sandbox")

    def sample_problems(self, *, seed: str, config: dict[str, Any]) -> {{BASE}}Problems:
        raise NotImplementedError("TODO sample_problems() for {{DISPLAY}} -- see kata-sn126.")

    def benchmark_identity(self, problems: {{BASE}}Problems) -> str:
        raise NotImplementedError("TODO benchmark_identity() for {{DISPLAY}} -- see kata-sn126.")

    def run_candidate(
        self, *, agent_path: str, problems: {{BASE}}Problems, context: RunContext
    ) -> {{BASE}}RawRun:
        raise NotImplementedError("TODO run_candidate() for {{DISPLAY}} -- see kata-sn126.")

    def score(self, raw: {{BASE}}RawRun, problems: {{BASE}}Problems) -> ScoreCard:
        raise NotImplementedError("TODO score() for {{DISPLAY}} -- see kata-sn126.")

    # compare() and beats_king() below are NOT stubs. They are generic over the ScoreCard contract
    # -- ranking by `comparable` and clearing the king by `beats_threshold` needs no subnet
    # knowledge -- so the scaffold ships working implementations. Override only if this subnet
    # ranks on something the single `comparable` scalar cannot express.

    def compare(self, a: ScoreCard, b: ScoreCard) -> int:
        # A failed run must never rank above a valid one (see ScoreCard.passed); after that, the
        # higher `comparable` wins.
        if a.passed != b.passed:
            return 1 if a.passed else -1
        return (a.comparable > b.comparable) - (a.comparable < b.comparable)

    def beats_king(self, candidate: ScoreCard, king: ScoreCard | None) -> bool:
        # A challenger must be a valid run, and must clear the king by its own declared margin
        # (`beats_threshold`; 0.0 means strict greater-than). No king yet == any valid run wins.
        if not candidate.passed:
            return False
        if king is None:
            return True
        return candidate.comparable > king.comparable + candidate.beats_threshold
'''

_TEST_PLUGIN = '''\
from __future__ import annotations

import {{PACKAGE}}
from kata.plugins.contract import EnvSpec, ScoringProfile, SubnetPlugin
from kata.plugins.discovery import plugin_for_evaluator, plugin_for_pack


def test_singleton_is_a_subnet_plugin() -> None:
    assert isinstance({{PACKAGE}}.{{SINGLETON}}, SubnetPlugin)


def test_identity_attributes() -> None:
    plugin = {{PACKAGE}}.{{SINGLETON}}
    assert plugin.evaluator_id == "{{EVALUATOR}}"
    assert plugin.pack == "{{PACK}}"
    assert plugin.mode == "{{MODE}}"
    assert isinstance(plugin.scoring_profile, ScoringProfile)


def test_environment_spec_returns_envspec() -> None:
    assert isinstance({{PACKAGE}}.{{SINGLETON}}.environment_spec(), EnvSpec)


def test_discovery_resolves_by_evaluator_id_and_pack() -> None:
    assert plugin_for_evaluator("{{EVALUATOR}}") is {{PACKAGE}}.{{SINGLETON}}
    assert plugin_for_pack("{{PACK}}", "{{MODE}}") is {{PACKAGE}}.{{SINGLETON}}
'''

_README = '''\
# {{REPO}} — SN{{N}} ({{DISPLAY}}) subnet plugin

The **SN{{N}} / {{DISPLAY}}** subnet plugin for [Kata](https://github.com/Autovara/kata),
scaffolded by `kata-forge`. Fill the four subnet-specific methods to make it compete — no
changes to `kata` core or `kata-board` are needed.

## TODO (scaffolded stubs)

- [ ] `sample_problems` + `benchmark_identity` — the pinned task set + a deterministic id
- [ ] `run_candidate` — run the agent (egress-blocked)
- [ ] `score` — grade a run into a `ScoreCard` (+ metrics)
- [ ] `compare` / `beats_king` — order results

See **`kata-sn126`** for a worked reference and `deploy/lane-config.md` to wire the lane.

## Dev

```bash
uv venv && uv pip install -e ../kata -e '.[dev]'
.venv/bin/python -m pytest -q
```
'''

_GITIGNORE = '''\
.venv/
__pycache__/
*.pyc
.pytest_cache/
.ruff_cache/
*.egg-info/
dist/
build/
'''

_LANE_CONFIG = '''\
# Wiring the SN{{N}} lane (config only)

Onboarding SN{{N}} needs **no code change in `kata` core or `kata-board`, only config in
`kata-bot`**. This is a go-live step (not applied by scaffolding).

## 1. Install the plugin into the validator env

```bash
uv pip install -e /srv/{{REPO}}
python -c "from kata.plugins.discovery import plugin_for_evaluator as p; print(p('{{EVALUATOR}}'))"
```

## 2. Add the lane to `kata-bot` config (`.env`)

Append one entry to `KATA_LANES` (keep existing lanes) and add the plugin path to
`KATA_SUBNET_PLUGIN_EDITABLE_PATHS`:

```bash
# ...existing lanes...,
{"lane_id":"{{PACK}}","pack":"{{PACK}}","mode":"{{MODE}}","evaluator":"{{EVALUATOR}}",
 "source_repos":["Autovara/{{REPO}}"],
 "challenge_config":{}}

KATA_SUBNET_PLUGIN_EDITABLE_PATHS=...,/srv/{{REPO}}
```

`challenge_config` is passed straight to `sample_problems(seed, config)` — add this subnet's keys
(e.g. a pinned benchmark path, sample size). Then restart the validator.
'''

#: relative-path template -> file-content template.
TEMPLATES: dict[str, str] = {
    "pyproject.toml": _PYPROJECT,
    "{{PACKAGE}}/__init__.py": _INIT,
    "{{PACKAGE}}/models.py": _MODELS,
    "{{PACKAGE}}/plugin.py": _PLUGIN,
    "tests/test_plugin.py": _TEST_PLUGIN,
    "README.md": _README,
    ".gitignore": _GITIGNORE,
    "deploy/lane-config.md": _LANE_CONFIG,
}
