"""S6: compartment policy, canaries, and bounded AI drafting (plan 6/7).

Policy assertions run everywhere (pure argv construction). The tests that prove ISOLATION need a
host that can build a namespace, and skip explicitly when it cannot — never silently passing, since
"the probe did not run" certifying "isolated" is the exact failure this section guards against.
"""
from __future__ import annotations

import json

import pytest

from kata_forge import canaries as cn
from kata_forge.ai_budget import (
    DEFAULT_MAX_ATTEMPTS,
    MAX_ATTEMPTS_ENV,
    MAX_INPUT_BYTES_ENV,
    MAX_OUTPUT_TOKENS_ENV,
    MAX_SPEND_USD_ENV,
    MAX_WALL_SECONDS_ENV,
    PROVIDER_ENFORCES_SPEND_ENV,
    AiBudget,
    AiBudgetExhausted,
    AiDraftingDisabled,
    AiUsage,
    limits_from_env,
    prompt_template_hash,
    write_ai_usage,
)
from kata_forge.compartment import (
    CLEAN_ENV,
    COMPARTMENTS,
    DRAFT,
    FETCH,
    SANDBOX_UID,
    VERIFY,
    CompartmentError,
    build_argv,
    fresh_workspace,
    run_in_compartment,
)

CONFIGURED = {
    MAX_WALL_SECONDS_ENV: "600",
    MAX_INPUT_BYTES_ENV: "100000",
    MAX_OUTPUT_TOKENS_ENV: "4000",
}


def _isolation_available() -> bool:
    """True only when a compartment can ACTUALLY be created on this host.

    Deliberately probes through the REAL code path rather than a hand-rolled bwrap command: a
    duplicated probe drifts from the policy it stands in for, and the first version of this one
    skipped every isolation test because it happened to omit a bind the real builder includes.
    """
    import tempfile

    try:
        with tempfile.TemporaryDirectory() as scratch:
            workspace = fresh_workspace(scratch, "probe")
            return run_in_compartment(DRAFT, ["/bin/true"], workspace=workspace).returncode == 0
    except Exception:  # noqa: BLE001 - any failure means "cannot isolate here"
        return False


needs_isolation = pytest.mark.skipif(
    not _isolation_available(),
    reason="this host cannot create a user namespace (needs bwrap + a root launcher)")


# ---- compartment policy (pure, runs everywhere) --------------------------------------------------
def test_only_fetch_has_network():
    """An AI step with egress is an exfiltration path; verification with egress is not verification."""
    assert FETCH.network is True
    assert DRAFT.network is False and VERIFY.network is False


def test_no_network_compartments_unshare_the_network_namespace(tmp_path):
    for compartment in (DRAFT, VERIFY):
        argv = build_argv(compartment, ["/bin/true"], workspace=tmp_path)
        assert "--unshare-net" in argv
    assert "--unshare-net" not in build_argv(FETCH, ["/bin/true"], workspace=tmp_path)


def test_every_compartment_drops_privilege_and_capabilities(tmp_path):
    for compartment in COMPARTMENTS.values():
        argv = build_argv(compartment, ["/bin/true"], workspace=tmp_path)
        assert argv[argv.index("--uid") + 1] == str(SANDBOX_UID)
        assert "--cap-drop" in argv and argv[argv.index("--cap-drop") + 1] == "ALL"
        assert "--unshare-pid" in argv and "--unshare-user" in argv
        assert "--die-with-parent" in argv and "--new-session" in argv


def test_credential_roots_are_never_bound_into_a_compartment(tmp_path):
    """/srv, /home, /root and /etc are ABSENT from the namespace, not merely unreadable."""
    for compartment in COMPARTMENTS.values():
        argv = build_argv(compartment, ["/bin/true"], workspace=tmp_path)
        bound = {argv[i + 1] for i, token in enumerate(argv) if token in ("--ro-bind", "--bind")}
        for forbidden in ("/srv", "/home", "/root", "/etc"):
            assert not any(path == forbidden or path.startswith(forbidden + "/") for path in bound)


def test_the_workspace_is_the_only_writable_surface(tmp_path):
    argv = build_argv(DRAFT, ["/bin/true"], workspace=tmp_path)
    writable = [argv[i + 1] for i, token in enumerate(argv) if token == "--bind"]
    assert writable == [str(tmp_path.resolve())]


def test_the_tmpfs_is_mounted_before_the_workspace_bind(tmp_path):
    """Regression: bwrap applies mounts in order. Reversed, a /tmp tmpfs overlays a workspace living
    under /tmp and the workload silently starts in an empty directory that is not the caller's."""
    argv = build_argv(DRAFT, ["/bin/true"], workspace=tmp_path)
    assert argv.index("--tmpfs") < argv.index("--bind")


def test_the_compartment_environment_is_fresh_not_filtered(monkeypatch):
    """A filtered copy of os.environ leaks whatever the filter forgot -- and what it forgets is the
    newly added credential variable."""
    monkeypatch.setenv("GITHUB_TOKEN", "ghp_secret")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "leak")
    assert set(CLEAN_ENV) == {"PATH", "HOME", "LC_ALL", "GIT_TERMINAL_PROMPT", "GIT_CONFIG_NOSYSTEM"}
    assert "ghp_secret" not in str(CLEAN_ENV) and "leak" not in str(CLEAN_ENV)


def test_an_empty_command_is_refused(tmp_path):
    with pytest.raises(CompartmentError):
        build_argv(DRAFT, [], workspace=tmp_path)


def test_a_missing_readonly_input_is_refused(tmp_path):
    with pytest.raises(CompartmentError, match="does not exist"):
        build_argv(DRAFT, ["/bin/true"], workspace=tmp_path,
                   ro_extra=(str(tmp_path / "absent"),))


def test_a_fresh_workspace_carries_nothing_over(tmp_path):
    first = fresh_workspace(tmp_path, "ws")
    (first / "leftover").write_text("state", encoding="utf-8")
    second = fresh_workspace(tmp_path, "ws")
    assert second == first and not (second / "leftover").exists()


# ---- canary logic (pure) -------------------------------------------------------------------------
def test_an_unrunnable_canary_is_never_a_pass():
    result = cn.CanaryResult(compartment="draft", probe="read:x", blocked=False, inconclusive=True)
    assert not result.passed
    with pytest.raises(cn.CanaryFailure, match="not a pass"):
        cn.assert_all_canaries_blocked([result])


def test_an_empty_canary_set_cannot_certify():
    with pytest.raises(cn.CanaryFailure, match="empty"):
        cn.assert_all_canaries_blocked([])


def test_a_reached_resource_fails_the_assertion():
    with pytest.raises(cn.CanaryFailure, match="REACHED"):
        cn.assert_all_canaries_blocked([
            cn.CanaryResult(compartment="draft", probe="read:/srv/kata-bot/.env", blocked=False)])


def test_the_egress_probe_does_not_use_dash():
    """Regression: /bin/sh on Debian/Ubuntu is dash, which has no /dev/tcp -- a shell connect probe
    reports 'blocked' for a fully connected compartment, certifying isolation that is not there."""
    argv = cn._probe_connect("1.1.1.1", 443)
    assert argv[0].endswith("python3")
    assert "/dev/tcp" not in " ".join(argv)


def test_the_credential_list_covers_the_real_secrets():
    assert "/srv/kata-bot/.env" in cn.CREDENTIAL_PATHS       # GitHub token + webhook secret
    assert "/srv/kata-subnets/approvals" in cn.CREDENTIAL_PATHS  # installer approval records
    assert any(".ssh" in path for path in cn.CREDENTIAL_PATHS)


# ---- canaries against a REAL compartment ---------------------------------------------------------
@needs_isolation
def test_no_credential_is_reachable_from_any_compartment(tmp_path):
    results = cn.run_credential_canaries(tmp_path)
    cn.assert_all_canaries_blocked(results)
    assert len(results) == len(cn.CREDENTIAL_PATHS) * len(COMPARTMENTS)


@needs_isolation
def test_no_egress_from_draft_or_verify(tmp_path):
    results = cn.run_egress_canaries(tmp_path)
    cn.assert_all_canaries_blocked(results)


@needs_isolation
def test_the_read_canary_can_actually_observe_a_reach(tmp_path):
    """NEGATIVE CONTROL. /usr/bin/env IS bound read-only, so this probe must report REACHED. A
    canary that always says 'blocked' certifies nothing."""
    result = cn._run_probe(DRAFT, "control", cn._probe_read("/usr/bin/env"), tmp_path)
    assert not result.blocked and not result.inconclusive


@needs_isolation
def test_the_egress_canary_can_actually_observe_a_connection(tmp_path):
    """NEGATIVE CONTROL. Fetch legitimately has network, so this probe must report REACHED."""
    result = cn._run_probe(FETCH, "control", cn._probe_connect("1.1.1.1", 443), tmp_path)
    assert not result.blocked, "the egress probe cannot observe a connection; its results are void"


@needs_isolation
def test_untrusted_code_runs_as_the_sandbox_uid(tmp_path):
    workspace = fresh_workspace(tmp_path, "uid")
    run = run_in_compartment(VERIFY, ["/usr/bin/id", "-u"], workspace=workspace)
    assert run.stdout.strip() == str(SANDBOX_UID)


@needs_isolation
def test_a_compartment_cannot_write_outside_its_workspace(tmp_path):
    workspace = fresh_workspace(tmp_path, "ro")
    run = run_in_compartment(VERIFY, ["/bin/sh", "-c", "echo x > /usr/pwned"], workspace=workspace)
    assert run.returncode != 0 and not (tmp_path / "pwned").exists()


# ---- AI budget: disabled unless fully configured -------------------------------------------------
@pytest.mark.parametrize("missing", [MAX_WALL_SECONDS_ENV, MAX_INPUT_BYTES_ENV, MAX_OUTPUT_TOKENS_ENV])
def test_drafting_stays_disabled_when_any_bound_is_unset(missing):
    env = {k: v for k, v in CONFIGURED.items() if k != missing}
    with pytest.raises(AiDraftingDisabled, match=missing):
        limits_from_env(env)


@pytest.mark.parametrize("bad", ["0", "-1", "not-a-number"])
def test_a_non_positive_bound_disables_drafting(bad):
    with pytest.raises(AiDraftingDisabled):
        limits_from_env({**CONFIGURED, MAX_INPUT_BYTES_ENV: bad})


def test_attempts_defaults_but_the_rest_must_be_explicit():
    limits = limits_from_env(CONFIGURED)
    assert limits.max_attempts == DEFAULT_MAX_ATTEMPTS
    assert limits_from_env({**CONFIGURED, MAX_ATTEMPTS_ENV: "5"}).max_attempts == 5


def test_usd_is_observation_only_unless_the_provider_enforces_it():
    """The same honesty rule as the runtime budget: an unenforceable number is not a cap."""
    soft = limits_from_env({**CONFIGURED, MAX_SPEND_USD_ENV: "5"})
    assert soft.max_spend_usd == 5 and not soft.spend_is_hard_cap
    assert soft.as_evidence()["spend_enforcement"] == "observation-only"

    hard = limits_from_env({**CONFIGURED, MAX_SPEND_USD_ENV: "5",
                            PROVIDER_ENFORCES_SPEND_ENV: "1"})
    assert hard.spend_is_hard_cap
    assert hard.as_evidence()["spend_enforcement"] == "hard-cap"


# ---- AI budget: enforcement ----------------------------------------------------------------------
def _budget(**over):
    limits = limits_from_env({**CONFIGURED, **over})
    return AiBudget(limits, AiUsage(build_id="b1", provider="p", model="m", limits=limits))


def test_the_budget_is_checked_before_the_call_not_after():
    budget = _budget(**{MAX_INPUT_BYTES_ENV: "100"})
    budget.check_before_call(prompt_bytes=90, attempt=1)  # fits
    with pytest.raises(AiBudgetExhausted, match="input"):
        budget.check_before_call(prompt_bytes=101, attempt=1)  # would exceed -> refused BEFORE


def test_attempt_exhaustion_refuses():
    budget = _budget(**{MAX_ATTEMPTS_ENV: "2"})
    budget.check_before_call(prompt_bytes=1, attempt=2)
    with pytest.raises(AiBudgetExhausted, match="attempt"):
        budget.check_before_call(prompt_bytes=1, attempt=3)


def test_wall_clock_exhaustion_refuses():
    ticks = iter([0.0, 601.0])  # __init__ stamps the start, check_before_call reads the second
    limits = limits_from_env(CONFIGURED)
    budget = AiBudget(limits, AiUsage(build_id="b", provider="p", model="m", limits=limits),
                      clock=lambda: next(ticks))
    with pytest.raises(AiBudgetExhausted, match="600"):
        budget.check_before_call(prompt_bytes=1, attempt=1)


def test_a_provider_that_ignores_the_output_cap_is_a_violation():
    budget = _budget(**{MAX_OUTPUT_TOKENS_ENV: "100"})
    with pytest.raises(AiBudgetExhausted, match="output tokens"):
        budget.record_attempt(method="score", attempt=1, template_hash="h", prompt_bytes=10,
                              input_tokens=5, output_tokens=101, elapsed=1.0, result="ok")


def test_spend_is_only_enforced_when_it_is_a_hard_cap():
    soft = _budget(**{MAX_SPEND_USD_ENV: "1"})
    soft.usage.spend_usd = 99.0
    soft.check_before_call(prompt_bytes=1, attempt=1)  # observation-only: does not block

    hard = _budget(**{MAX_SPEND_USD_ENV: "1", PROVIDER_ENFORCES_SPEND_ENV: "1"})
    hard.usage.spend_usd = 99.0
    with pytest.raises(AiBudgetExhausted, match="spend"):
        hard.check_before_call(prompt_bytes=1, attempt=1)


# ---- AI provenance: counts, never content --------------------------------------------------------
def test_usage_records_counts_and_hashes_but_no_content(tmp_path):
    budget = _budget()
    template = "Draft the body of {method} from {anchor}. Return Python only."
    budget.record_attempt(method="score", attempt=1, template_hash=prompt_template_hash(template),
                          prompt_bytes=1234, input_tokens=300, output_tokens=120, elapsed=2.5,
                          result="passed", redactions=2)
    path, digest = write_ai_usage(tmp_path / "ai-usage.json", budget.usage)
    body = path.read_text()
    document = json.loads(body)

    assert document["build_id"] == "b1" and document["attempts"][0]["result"] == "passed"
    assert document["totals"]["redaction_count"] == 2
    assert document["attempts"][0]["prompt_template_sha256"] == prompt_template_hash(template)
    # The TEMPLATE hash, never the filled prompt: a filled prompt contains source text.
    assert template not in body and "Draft the body" not in body
    assert len(digest) == 64  # the manifest carries this, so provenance is approval-covered


def test_record_attempt_has_no_parameter_that_could_carry_a_prompt():
    """Structural: there is no seam through which raw prompt text, source, or a credential could
    enter the provenance file."""
    import inspect

    parameters = set(inspect.signature(AiBudget.record_attempt).parameters)
    for forbidden in ("prompt", "text", "content", "source", "response", "output"):
        assert forbidden not in parameters
