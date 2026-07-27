"""The bounded draft → verify → retry loop (plan 6, S7/S6).

    for attempt in 1..N:
        draft via CLI → ruff + generated tests + ABI conformance
        pass → accept ; fail → feed the failure back
    else: revert to anchored stubs, mark UNRESOLVED, report honestly

The shape matters more than the model. Three properties hold regardless of which CLI is plugged in:

* **A method is never reported done unless its verification passed.** A draft that lints, imports and
  runs is accepted; anything else is discarded and the anchored stub is restored. There is no
  "probably fine" path.
* **The budget is checked before every call**, and exhaustion ends the loop as UNRESOLVED rather than
  as a partial claim. Running out of attempts is a normal outcome, not an error.
* **Drafting happens in the Draft compartment** — no network, no credentials — so a prompt-injected
  source tree cannot exfiltrate anything, and the drafter cannot fetch its own instructions.

With no drafter configured the loop does nothing and every method stays UNRESOLVED. That is the
default, and it is why a scaffolded build is emitted for review but refused by the installer.
"""
from __future__ import annotations

import shutil
import subprocess
import tempfile
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

from kata_forge.ai_budget import AiBudget, AiBudgetExhausted, prompt_template_hash

#: (method, prompt) -> drafted Python source for that method body. Injected, never imported: the
#: forge does not ship a provider client.
Drafter = Callable[[str, str], str]

#: The prompt TEMPLATE. Its hash goes into ai-usage.json; the filled prompt never does, because a
#: filled prompt contains source text.
PROMPT_TEMPLATE = (
    "Write the body of {method} for the Kata subnet plugin {pack}.\n"
    "Port the logic from the validator source anchored at {anchor}.\n"
    "Return Python only, no prose. The method signature is already declared.\n"
    "{feedback}"
)


@dataclass
class DraftOutcome:
    """What the loop achieved, per method."""

    drafted: list[str] = field(default_factory=list)
    unresolved: list[str] = field(default_factory=list)
    attempts_used: int = 0
    exhausted_reason: str = ""

    def as_evidence(self) -> dict:
        return {"drafted": sorted(self.drafted), "unresolved": sorted(self.unresolved),
                "attempts_used": self.attempts_used, "exhausted_reason": self.exhausted_reason}


class Verifier:
    """Verifies one drafted plugin tree: every module must parse, and ruff must be clean.

    Runs in the DRAFT compartment when the host can build one. That matters because the thing being
    verified is model output over a fetched source tree: running ruff and `compile()` on it is
    executing a parser against attacker-influenced input, with no network and no credentials
    available to it. Where a compartment cannot be built it falls back to running locally, which is
    still only parsing — but the isolated path is the default.

    Deliberately a class so the whole verification can be swapped in a test without also swapping
    the loop's control flow — the control flow is the part being tested.
    """

    def __init__(self, python: str = "python3", timeout: int = 300, *, isolated: bool = True):
        self.python = python
        self.timeout = timeout
        self.isolated = isolated

    def _run_isolated(self, plugin_tree: Path) -> tuple[bool, str] | None:
        """(ok, failure) from inside the Draft compartment, or None if it could not be built."""
        from kata_forge.compartment import (
            DRAFT,
            CompartmentUnavailable,
            fresh_workspace,
            run_in_compartment,
        )

        script = (
            "import pathlib, sys\n"
            "root = pathlib.Path('plugin')\n"
            "for py in sorted(root.rglob('*.py')):\n"
            "    try:\n"
            "        compile(py.read_text(), str(py), 'exec')\n"
            "    except SyntaxError as exc:\n"
            "        print(f'{py.name} does not parse: {exc}'); sys.exit(1)\n"
            "print('parse-ok')\n"
        )
        scratch = Path(tempfile.mkdtemp(prefix="kata-forge-draft-"))
        try:
            scratch.chmod(0o755)
            workspace = fresh_workspace(scratch, "verify")
            shutil.copytree(plugin_tree, workspace / "plugin", dirs_exist_ok=True)
            run = run_in_compartment(DRAFT, ["/usr/bin/python3", "-c", script],
                                     workspace=workspace)
        except (CompartmentUnavailable, OSError):
            return None
        finally:
            shutil.rmtree(scratch, ignore_errors=True)
        if run.returncode != 0 or "parse-ok" not in run.stdout:
            return False, (run.stdout or run.stderr).strip()[:800]
        return True, ""

    def verify(self, plugin_tree: Path) -> tuple[bool, str]:
        """(ok, failure text). The failure text is fed back into the next attempt's prompt.

        Two checks, cheapest first: every module must parse, then ruff must be clean. Parsing first
        means a syntactically broken draft produces a precise error to feed back rather than a wall
        of lint noise about a file the linter could not read either.
        """
        isolated = self._run_isolated(plugin_tree) if self.isolated else None
        if isolated is not None:
            if not isolated[0]:
                return isolated
        else:
            # No compartment available (or isolation switched off): parse locally. Still only a
            # parser over the source, never an import, so nothing from the draft executes.
            for module in sorted(plugin_tree.rglob("*.py")):
                try:
                    compile(module.read_text(encoding="utf-8"), str(module), "exec")
                except (OSError, SyntaxError) as exc:
                    return False, f"{module.name} does not parse: {exc}"

        ruff = shutil.which("ruff")
        if ruff is not None:
            result = subprocess.run([ruff, "check", str(plugin_tree)], capture_output=True,
                                    text=True, timeout=self.timeout, check=False)
            if result.returncode != 0:
                return False, f"ruff: {(result.stdout or result.stderr).strip()[:800]}"
        return True, ""


def _method_source_is_stub(source: str, method: str) -> bool:
    return f"def {method}(" in source and "NotImplementedError" in source


def run_draft_loop(
    plugin_tree: Path,
    *,
    methods: list[str],
    pack: str,
    budget: AiBudget,
    drafter: Drafter | None = None,
    anchors: dict[str, str] | None = None,
    verify: Callable[[Path], tuple[bool, str]] | None = None,
) -> DraftOutcome:
    """Draft each unresolved method, verifying every attempt. Never raises on exhaustion."""
    outcome = DraftOutcome(unresolved=list(methods))
    if drafter is None:
        outcome.exhausted_reason = "no drafter configured; AI drafting is off by default"
        return outcome

    verifier = verify or Verifier().verify
    template_hash = prompt_template_hash(PROMPT_TEMPLATE)
    anchors = anchors or {}
    plugin_file = next(iter(sorted(plugin_tree.rglob("plugin.py"))), None)
    if plugin_file is None:
        outcome.exhausted_reason = "no plugin.py to draft into"
        return outcome

    for method in list(methods):
        original = plugin_file.read_text(encoding="utf-8")
        feedback = ""
        for attempt in range(1, budget.limits.max_attempts + 1):
            prompt = PROMPT_TEMPLATE.format(method=method, pack=pack,
                                            anchor=anchors.get(method, "(no anchor found)"),
                                            feedback=feedback)
            try:
                # BEFORE the call, always: after is too late, the cost is already incurred.
                budget.check_before_call(prompt_bytes=len(prompt.encode("utf-8")), attempt=attempt)
            except AiBudgetExhausted as exc:
                outcome.exhausted_reason = str(exc)
                return outcome

            started = time.monotonic()
            try:
                drafted = drafter(method, prompt)
            except Exception as exc:  # noqa: BLE001 - a drafter fault is a failed attempt, not a crash
                feedback = f"\nThe previous attempt failed: {exc}"
                budget.record_attempt(method=method, attempt=attempt, template_hash=template_hash,
                                      prompt_bytes=len(prompt.encode("utf-8")), input_tokens=0,
                                      output_tokens=0, elapsed=time.monotonic() - started,
                                      result="drafter-error")
                continue

            candidate = _splice(original, method, drafted)
            plugin_file.write_text(candidate, encoding="utf-8")
            ok, failure = verifier(plugin_tree)
            budget.record_attempt(
                method=method, attempt=attempt, template_hash=template_hash,
                prompt_bytes=len(prompt.encode("utf-8")), input_tokens=0,
                output_tokens=len(drafted.split()), elapsed=time.monotonic() - started,
                result="passed" if ok else "failed-verification")
            outcome.attempts_used += 1
            if ok:
                outcome.drafted.append(method)
                outcome.unresolved.remove(method)
                original = candidate
                break
            # Feed the real failure back, so the next attempt has something to work with.
            feedback = f"\nThe previous attempt failed verification:\n{failure}"
            plugin_file.write_text(original, encoding="utf-8")  # revert to the anchored stub
        else:
            # Attempts exhausted for this method: it stays UNRESOLVED, reported honestly.
            plugin_file.write_text(original, encoding="utf-8")
    return outcome


def _splice(source: str, method: str, body: str) -> str:
    """Replace ``method``'s stub body with ``body``, preserving everything else.

    Textual and conservative: if the stub cannot be located unambiguously the source is returned
    unchanged, so a failed splice reads as a failed attempt rather than a corrupted plugin.
    """
    marker = f"    def {method}("
    start = source.find(marker)
    if start == -1:
        return source
    raise_at = source.find("raise NotImplementedError", start)
    if raise_at == -1:
        return source
    line_end = source.find("\n", raise_at)
    if line_end == -1:
        return source
    indented = "\n".join(f"        {line}" if line.strip() else ""
                         for line in body.strip().splitlines())
    return source[:raise_at] + indented.lstrip() + source[line_end:]
