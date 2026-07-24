"""Emit the kata-bot lane config for a subnet as a reviewable artifact.

Given a spec, produce (a) the single ``KATA_LANES`` entry + editable-path addition, as a
human-readable snippet, and (b) a unified ``.patch`` against an existing ``.env`` that adds
them idempotently. **It never writes the ``.env``** -- the operator reviews and applies.
"""

from __future__ import annotations

import difflib
import json
import re
from typing import Any

from kata_forge.spec import SubnetSpec

DEFAULT_ORG = "Autovara"
DEFAULT_SRV_ROOT = "/srv"
_LANES_KEY = "KATA_LANES"
_PATHS_KEY = "KATA_SUBNET_PLUGIN_EDITABLE_PATHS"


def editable_path(spec: SubnetSpec, srv_root: str = DEFAULT_SRV_ROOT) -> str:
    return f"{srv_root.rstrip('/')}/{spec.repo_name}"


def lane_entry(
    spec: SubnetSpec,
    *,
    org: str = DEFAULT_ORG,
    release_path: str | None = None,
    sample_size: int | None = None,
    allowed_hosts: list[str] | None = None,
    required_secrets: list[str] | None = None,
) -> dict[str, Any]:
    """The one ``KATA_LANES`` entry for this subnet.

    For a paid/networked subnet, ``allowed_hosts`` + ``required_secrets`` add an ``egress`` block
    documenting the proxy allowlist and the secrets the operator must supply (names only).
    """
    challenge_config: dict[str, Any] = {}
    if release_path:
        challenge_config["pinned_release_path"] = release_path
    if sample_size:
        challenge_config["sample_size"] = int(sample_size)
    entry: dict[str, Any] = {
        "lane_id": spec.pack,
        "pack": spec.pack,
        "mode": spec.mode,
        "evaluator": spec.evaluator_id,
        "source_repos": [f"{org}/{spec.repo_name}"],
        "challenge_config": challenge_config,
    }
    if allowed_hosts or required_secrets:
        entry["egress"] = {
            "allowed_hosts": sorted(allowed_hosts or []),
            "required_secrets": sorted(required_secrets or []),
        }
    return entry


def secret_placeholder_block(required_secrets: list[str], subnet_number: int) -> list[str]:
    """Commented ``.env`` placeholder lines for the operator to fill (never a real value)."""
    if not required_secrets:
        return []
    block = [f"# --- SN{subnet_number} lane secrets (fill in; do NOT commit real values) ---"]
    block += [f"# {name}=" for name in sorted(required_secrets)]
    return block


def render_snippet(spec: SubnetSpec, entry: dict[str, Any], path: str) -> str:
    """A human-readable go-live block: the lane entry + editable path + install/restart."""
    return "\n".join(
        [
            f"# Add the SN{spec.subnet_number} lane to kata-bot (.env) -- keep existing lanes:",
            "",
            f"# 1. install:  uv pip install -e {path}",
            f"# 2. append this object to {_LANES_KEY}:",
            "     " + json.dumps(entry, separators=(",", ":")),
            f"# 3. append to {_PATHS_KEY} (comma-separated):",
            f"     ,{path}",
            "# 4. restart the validator.",
        ]
    )


def _split_env_value(line: str, key: str) -> str | None:
    prefix = f"{key}="
    if not line.startswith(prefix):
        return None
    value = line[len(prefix) :]
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
        value = value[1:-1]
    return value


def apply_lane_to_env(
    env_text: str, entry: dict[str, Any], path: str, *, secret_placeholders: list[str] | None = None
) -> str:
    """Return ``env_text`` with the lane entry + editable path added (idempotent).

    ``secret_placeholders`` appends commented ``# NAME=`` lines for any secret not already present,
    so a paid subnet's keys are surfaced for the operator without ever writing a value.
    """
    lines = env_text.splitlines()
    lanes_done = paths_done = False
    for index, line in enumerate(lines):
        raw_lanes = _split_env_value(line, _LANES_KEY)
        if raw_lanes is not None:
            lanes = json.loads(raw_lanes) if raw_lanes.strip() else []
            if not any(existing.get("lane_id") == entry["lane_id"] for existing in lanes):
                lanes.append(entry)
            lines[index] = f"{_LANES_KEY}='{json.dumps(lanes, separators=(',', ':'))}'"
            lanes_done = True
            continue
        raw_paths = _split_env_value(line, _PATHS_KEY)
        if raw_paths is not None:
            # Comma-separated to match the kata-bot consumer (orchestrator.subnet_plugin_uv_args
            # splits on ","). A colon join looked path-like but produced one bogus --with-editable
            # token for a second lane, breaking plugin discovery. We also split on ":" so a LEGACY
            # colon-joined value written by the old generator is migrated to commas instead of being
            # left as one invalid token. ":" is never a valid separator for this var (the consumer
            # only splits on ","), and Kata plugin paths never contain ":", so this is safe.
            paths = [segment.strip() for segment in re.split(r"[,:]", raw_paths) if segment.strip()]
            if path not in paths:
                paths.append(path)
            lines[index] = f"{_PATHS_KEY}={','.join(paths)}"
            paths_done = True
    if not lanes_done:
        lines.append(f"{_LANES_KEY}='{json.dumps([entry], separators=(',', ':'))}'")
    if not paths_done:
        lines.append(f"{_PATHS_KEY}={path}")
    for name in secret_placeholders or []:
        if f"{name}=" not in env_text:  # skip secrets already set or already placeheld
            lines.append(f"# {name}=")
    trailing = "\n" if env_text.endswith("\n") else ""
    return "\n".join(lines) + trailing


def env_patch(
    env_text: str,
    entry: dict[str, Any],
    path: str,
    *,
    env_path: str = "/srv/kata-bot/.env",
    secret_placeholders: list[str] | None = None,
) -> str:
    """A unified diff adding the lane to ``env_text``; empty string if already present."""
    modified = apply_lane_to_env(env_text, entry, path, secret_placeholders=secret_placeholders)
    if modified == env_text:
        return ""
    rel = env_path.lstrip("/")  # git-style a/<path>, no double slash on an absolute path
    diff = difflib.unified_diff(
        env_text.splitlines(keepends=True),
        modified.splitlines(keepends=True),
        fromfile=f"a/{rel}",
        tofile=f"b/{rel}",
    )
    return "".join(diff)
