"""S6/S7: the bounded draft -> verify -> retry loop (plan 6).

The model is swappable; the control flow is what these pin down. A method is never reported done
unless its verification passed, exhaustion is an honest UNRESOLVED rather than a partial claim, and
the budget is consulted before every call.
"""
from __future__ import annotations

import ast

import pytest

from kata_forge.ai_budget import AiBudget, AiUsage, limits_from_env
from kata_forge.draft_loop import PROMPT_TEMPLATE, Verifier, run_draft_loop

CONFIGURED = {
    "KATA_FORGE_AI_MAX_WALL_SECONDS": "600",
    "KATA_FORGE_AI_MAX_INPUT_BYTES": "1000000",
    "KATA_FORGE_AI_MAX_OUTPUT_TOKENS": "4000",
}

STUB_PLUGIN = '''\
class P:
    def score(self, raw, problems):
        raise NotImplementedError("TODO score() -- see kata-sn126.")

    def compare(self, a, b):
        return 0
'''


def _budget(**over):
    limits = limits_from_env({**CONFIGURED, **over})
    return AiBudget(limits, AiUsage(build_id="b", provider="p", model="m", limits=limits))


@pytest.fixture
def plugin_tree(tmp_path):
    tree = tmp_path / "kata-sn44" / "kata_sn44"
    tree.mkdir(parents=True)
    (tree / "plugin.py").write_text(STUB_PLUGIN, encoding="utf-8")
    return tree.parent


def _ok_verify(_tree):
    return True, ""


def _bad_verify(_tree):
    return False, "ruff: E999 invalid syntax"


# ---- the default: drafting is off ---------------------------------------------------------------
def test_with_no_drafter_every_method_stays_unresolved(plugin_tree):
    outcome = run_draft_loop(plugin_tree, methods=["score"], pack="sn44__poker44",
                             budget=_budget())
    assert outcome.unresolved == ["score"] and outcome.drafted == []
    assert "off by default" in outcome.exhausted_reason


def test_a_drafter_without_an_authoritative_verifier_is_never_called(plugin_tree):
    calls = []
    outcome = run_draft_loop(
        plugin_tree,
        methods=["score"],
        pack="sn44__poker44",
        budget=_budget(),
        drafter=lambda method, prompt: calls.append((method, prompt)) or "return 42",
    )
    assert calls == []
    assert outcome.unresolved == ["score"]
    assert "authoritative subnet verifier" in outcome.exhausted_reason


# ---- a passing draft is accepted ----------------------------------------------------------------
def test_a_verified_draft_is_accepted_and_spliced(plugin_tree):
    outcome = run_draft_loop(
        plugin_tree, methods=["score"], pack="sn44__poker44", budget=_budget(),
        drafter=lambda method, prompt: "return 42", verify=_ok_verify)

    assert outcome.drafted == ["score"] and outcome.unresolved == []
    body = (plugin_tree / "kata_sn44" / "plugin.py").read_text()
    assert "return 42" in body and "NotImplementedError" not in body
    ast.parse(body)
    assert "    def score(self, raw, problems):\n        return 42\n" in body


# ---- a failing draft is never accepted ----------------------------------------------------------
def test_a_draft_that_fails_verification_is_reverted_not_accepted(plugin_tree):
    outcome = run_draft_loop(
        plugin_tree, methods=["score"], pack="sn44__poker44", budget=_budget(),
        drafter=lambda method, prompt: "return 'broken'", verify=_bad_verify)

    assert outcome.unresolved == ["score"] and outcome.drafted == []
    # The anchored stub is restored -- a rejected draft must leave no trace.
    body = (plugin_tree / "kata_sn44" / "plugin.py").read_text()
    assert "NotImplementedError" in body and "broken" not in body


def test_the_failure_is_fed_back_into_the_next_attempt(plugin_tree):
    seen: list[str] = []

    def drafter(method, prompt):
        seen.append(prompt)
        return "return 1"

    run_draft_loop(plugin_tree, methods=["score"], pack="sn44__poker44",
                   budget=_budget(KATA_FORGE_AI_MAX_ATTEMPTS="3"),
                   drafter=drafter, verify=_bad_verify)

    assert len(seen) == 3, "it must use its whole attempt budget before giving up"
    assert "E999 invalid syntax" in seen[1], "attempt 2 must know why attempt 1 failed"


def test_attempts_are_bounded_and_exhaustion_is_honest(plugin_tree):
    outcome = run_draft_loop(plugin_tree, methods=["score"], pack="sn44__poker44",
                             budget=_budget(KATA_FORGE_AI_MAX_ATTEMPTS="2"),
                             drafter=lambda m, p: "return 1", verify=_bad_verify)
    assert outcome.attempts_used == 2 and outcome.unresolved == ["score"]


def test_a_raising_drafter_is_a_failed_attempt_not_a_crash(plugin_tree):
    def boom(_method, _prompt):
        raise RuntimeError("provider timeout")

    budget = _budget(KATA_FORGE_AI_MAX_ATTEMPTS="2")
    outcome = run_draft_loop(plugin_tree, methods=["score"], pack="sn44__poker44",
                             budget=budget, drafter=boom, verify=_ok_verify)

    assert outcome.unresolved == ["score"], "a provider failure must not report the method done"
    # The failed attempts are still recorded, so a build that burned its budget on timeouts is
    # visible in the provenance rather than looking like it was never tried.
    assert [a["result"] for a in budget.usage.attempts] == ["drafter-error", "drafter-error"]


# ---- budget + provenance ------------------------------------------------------------------------
def test_the_budget_is_consulted_before_every_call(plugin_tree):
    budget = _budget(KATA_FORGE_AI_MAX_INPUT_BYTES="10")  # smaller than any prompt
    calls: list[str] = []
    outcome = run_draft_loop(plugin_tree, methods=["score"], pack="sn44__poker44", budget=budget,
                             drafter=lambda m, p: calls.append(m) or "return 1", verify=_ok_verify)
    assert calls == [], "the drafter must not be called once the budget cannot cover the prompt"
    assert outcome.unresolved == ["score"] and "input" in outcome.exhausted_reason


def test_provenance_records_attempts_without_prompt_text(plugin_tree):
    budget = _budget()
    run_draft_loop(plugin_tree, methods=["score"], pack="sn44__poker44", budget=budget,
                   drafter=lambda m, p: "return 1", verify=_ok_verify)

    attempts = budget.usage.attempts
    assert attempts and attempts[0]["result"] == "passed"
    assert attempts[0]["prompt_template_sha256"]  # the TEMPLATE hash, never the filled prompt
    assert PROMPT_TEMPLATE not in str(attempts)


# ---- the real verifier --------------------------------------------------------------------------
def test_the_real_verifier_rejects_a_draft_that_does_not_parse(plugin_tree):
    (plugin_tree / "kata_sn44" / "plugin.py").write_text("def broken(:\n", encoding="utf-8")
    ok, failure = Verifier().verify(plugin_tree)
    assert not ok and "does not parse" in failure


def test_the_real_verifier_accepts_clean_source(plugin_tree):
    ok, failure = Verifier().verify(plugin_tree)
    assert ok, failure


def test_a_splice_that_cannot_locate_the_stub_changes_nothing(plugin_tree):
    """A failed splice must read as a failed attempt, never as a corrupted plugin."""
    verify_calls = []
    outcome = run_draft_loop(plugin_tree, methods=["no_such_method"], pack="sn44__poker44",
                             budget=_budget(), drafter=lambda m, p: "return 1",
                             verify=lambda tree: verify_calls.append(tree) or (True, ""))
    body = (plugin_tree / "kata_sn44" / "plugin.py").read_text()
    assert body == STUB_PLUGIN
    assert outcome.drafted == []
    assert outcome.unresolved == ["no_such_method"]
    assert verify_calls == [], "an unchanged splice cannot be handed to a permissive verifier"


def test_a_provider_error_counts_as_an_attempt(plugin_tree):
    budget = _budget(KATA_FORGE_AI_MAX_ATTEMPTS="2")

    def fail(_method, _prompt):
        raise RuntimeError("provider unavailable")

    outcome = run_draft_loop(
        plugin_tree,
        methods=["score"],
        pack="sn44__poker44",
        budget=budget,
        drafter=fail,
        verify=_ok_verify,
    )

    assert outcome.attempts_used == 2
    assert len(budget.usage.attempts) == 2


def test_an_over_limit_response_is_recorded_reverted_and_left_unresolved(plugin_tree):
    budget = _budget(KATA_FORGE_AI_MAX_OUTPUT_TOKENS="1")
    outcome = run_draft_loop(
        plugin_tree,
        methods=["score"],
        pack="sn44__poker44",
        budget=budget,
        drafter=lambda _method, _prompt: "return 42",
        verify=_ok_verify,
    )

    assert outcome.unresolved == ["score"]
    assert outcome.drafted == []
    assert "over the requested" in outcome.exhausted_reason
    assert budget.usage.attempts[0]["result"] == "output-limit-violation"
    assert (plugin_tree / "kata_sn44" / "plugin.py").read_text() == STUB_PLUGIN


def test_the_verifier_isolates_by_default_and_still_rejects_bad_source(plugin_tree):
    """Verification runs in the Draft compartment where the host allows it. Either way it must
    reject source that does not parse -- isolation must not soften the check."""
    (plugin_tree / "kata_sn44" / "plugin.py").write_text("def broken(:\n", encoding="utf-8")
    ok, failure = Verifier().verify(plugin_tree)
    assert not ok and "does not parse" in failure


def test_the_verifier_refuses_when_isolation_is_disabled(plugin_tree):
    """There is no host fallback: disabling isolation is a failed verification."""
    assert Verifier(isolated=True).verify(plugin_tree)[0] is True
    assert Verifier(isolated=False).verify(plugin_tree)[0] is False

    (plugin_tree / "kata_sn44" / "plugin.py").write_text("class P:\n  def x(:\n", encoding="utf-8")
    assert Verifier(isolated=True).verify(plugin_tree)[0] is False
    assert Verifier(isolated=False).verify(plugin_tree)[0] is False
