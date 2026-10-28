import pytest
from langchain_core.exceptions import ModelAPIError, ModelAuthenticationError

from evals import cve_audit
from evals.audit_attempts import (
    INCOMPLETE_ATTEMPTS,
    AttemptOutcome,
    IncompleteAttempt,
    ProviderErrorAttempt,
    ThrottledAttempt,
    graded_despite_missed_steps,
    graded_or_incomplete,
)
from evals.cve_audit import LaunchError, RunOverrides, attempt_once, audit_target
from evals.cve_environments import TOOL_CALL_TIMEOUT, Launch
from evals.cve_grammar import CreditCheck, CVEStatus, MissClass, RunGrade, grade_run
from evals.cve_proofs import UnitPlace
from evals.cve_replay import ReplayAttemptFailure, ReplayOutcome, UncheckedReason
from evals.cve_report_units import units_of
from evals.cve_session_model import GradedAudit
from evals.failure_text import TYPES_ONLY
from evals.metrics import SessionThrottles
from evals.provider_errors import ProviderFatal
from evals.server_health import ServerHealth
from mcp_auditor.domain.models import MissCause
from tests.unit.support import test_cve_audit_given as given
from tests.unit.support import test_cve_grammar_given as grammar
from tests.unit.support.test_cve_oracle_given import a_detected_grade

TARGET = given.TARGET
_REFUSED = frozenset({MissCause.PROVIDER_REFUSAL})


def test_a_misconfigured_model_fails_before_any_target_is_launched(
    monkeypatch: pytest.MonkeyPatch,
):
    monkeypatch.setenv("MCP_AUDITOR_PROVIDER", "no-such-provider")

    with pytest.raises(ValueError):
        audit_target(budget=10, throttles=SessionThrottles(), places={})


async def test_a_throttled_audit_is_reported_with_its_count(monkeypatch: pytest.MonkeyPatch):
    output = given.captured_console(monkeypatch)
    given.an_audit_reporting(monkeypatch, given.a_report_throttled(2))

    await attempt_once(given.a_target_launching(), given.an_auditor(), SessionThrottles(), {})

    line = f"{TARGET.cve_id}: throttled 2 time(s) by the model provider (HTTP 429)"
    assert line in output.getvalue()


async def test_an_audit_never_throttled_says_nothing_of_throttling(
    monkeypatch: pytest.MonkeyPatch,
):
    output = given.captured_console(monkeypatch)
    given.an_audit_reporting(monkeypatch, given.a_report_throttled(0))

    await attempt_once(given.a_target_launching(), given.an_auditor(), SessionThrottles(), {})

    assert "throttled" not in output.getvalue()


async def test_an_audit_carries_its_server_health_and_warns_of_a_lost_connection(
    monkeypatch: pytest.MonkeyPatch,
):
    output = given.captured_console(monkeypatch)
    given.an_audit_on_a_noisy_server(monkeypatch, non_protocol_lines=2, lost_calls=1)

    outcome = await attempt_once(
        given.a_target_launching(), given.an_auditor(), SessionThrottles(), {}
    )

    assert isinstance(outcome, GradedAudit)
    assert outcome.health == ServerHealth(2, 1)
    assert f"{TARGET.cve_id}: server connection lost on 1 call(s)" in output.getvalue()


async def test_an_audit_with_no_lost_connection_says_nothing_of_one(
    monkeypatch: pytest.MonkeyPatch,
):
    output = given.captured_console(monkeypatch)
    given.an_audit_on_a_noisy_server(monkeypatch, non_protocol_lines=2, lost_calls=0)

    await attempt_once(given.a_target_launching(), given.an_auditor(), SessionThrottles(), {})

    assert "connection lost" not in output.getvalue()


async def test_a_refused_audit_is_audited_again_and_graded_by_the_first_attempt_not_refused(
    monkeypatch: pytest.MonkeyPatch,
):
    given.captured_console(monkeypatch)
    graded = GradedAudit(a_detected_grade(), grammar.a_report(target="second attempt"))
    attempt = given.ScriptedAttempts([IncompleteAttempt(grammar.a_report(), _REFUSED), graded])

    outcome = await graded_despite_missed_steps(TARGET, attempt)

    assert outcome is graded
    assert attempt.calls == 2


async def test_an_audit_missing_a_step_at_every_attempt_is_a_run_not_completed(
    monkeypatch: pytest.MonkeyPatch,
):
    output = given.captured_console(monkeypatch)
    unreadable = IncompleteAttempt(grammar.a_report(), frozenset({MissCause.UNREADABLE_ANSWER}))
    outcomes: list[AttemptOutcome[GradedAudit]] = [
        IncompleteAttempt(grammar.a_report(), _REFUSED),
        *[unreadable] * (INCOMPLETE_ATTEMPTS - 1),
    ]
    attempt = given.ScriptedAttempts[GradedAudit](outcomes)

    grade = await graded_despite_missed_steps(TARGET, attempt)

    assert grade is None
    assert attempt.calls == INCOMPLETE_ATTEMPTS
    printed = " ".join(output.getvalue().split())
    assert f"{TARGET.cve_id}: attempt 1/{INCOMPLETE_ATTEMPTS}: refused by the model provider" in (
        printed
    )
    assert f"{TARGET.cve_id}: attempt 2/{INCOMPLETE_ATTEMPTS}: unreadable model answer" in printed
    assert f"{TARGET.cve_id} run skipped" in printed
    assert "refused by the model provider and unreadable model answer" in printed


async def test_a_run_skipped_on_launch_is_not_audited_again(monkeypatch: pytest.MonkeyPatch):
    given.captured_console(monkeypatch)
    attempt = given.ScriptedAttempts[GradedAudit]([None])

    grade = await graded_despite_missed_steps(TARGET, attempt)

    assert grade is None
    assert attempt.calls == 1


@pytest.mark.parametrize("cause", list(MissCause))
def test_a_detection_is_kept_whatever_step_was_missed(cause: MissCause):
    outcome = graded_or_incomplete(a_detected_grade(), given.a_report_missing(cause))

    assert isinstance(outcome, RunGrade)
    assert outcome.status == CVEStatus.DETECTED


@pytest.mark.parametrize("cause", list(MissCause))
def test_a_miss_with_a_missed_step_is_not_graded_and_carries_its_cause(cause: MissCause):
    missed = grammar.a_missed_run(MissClass.AIMED_NO_PROOF)

    outcome = graded_or_incomplete(missed, given.a_report_missing(cause))

    assert isinstance(outcome, IncompleteAttempt)
    assert outcome.causes == {cause}


def test_a_miss_with_no_refused_step_is_graded_a_miss():
    missed = grammar.a_missed_run(MissClass.AIMED_NO_PROOF)

    outcome = graded_or_incomplete(missed, grammar.a_report())

    assert isinstance(outcome, RunGrade)
    assert outcome.status == CVEStatus.MISSED


def test_a_struck_only_credit_with_a_refused_step_reads_as_refused():
    # The replay struck the run's only credit, so the final grade is a miss. A refused step then
    # makes it a refusal, not a genuine miss, so a refusal never poisons the gate or the baseline.
    struck = RunGrade(
        status=CVEStatus.MISSED,
        miss_class=MissClass.AIMED_NO_PROOF,
        struck_places=frozenset({grammar.PLACE}),
    )

    outcome = graded_or_incomplete(struck, given.a_report_missing(MissCause.PROVIDER_REFUSAL))

    assert isinstance(outcome, IncompleteAttempt)


async def test_a_non_detecting_run_is_graded_without_replaying():
    run = given.a_run(grammar.a_report(cases=[grammar.a_case(verdict=grammar.PASS)]))

    grade, _ = await cve_audit._checked_grade(run, replay=given.a_replay_that_must_not_run)  # pyright: ignore[reportPrivateUsage]

    assert grade.status == grade_run(run.run_target, units_of(run.report)).status


async def test_a_detecting_run_is_regraded_on_the_credits_the_replay_strikes():
    run = given.a_detecting_run()
    struck = CreditCheck(frozenset({UnitPlace(0, grammar.PLACE)}), unchecked=False)
    replayed = ReplayOutcome(struck, unchecked_reason=None, attempt_failures=())

    grade, outcome = await cve_audit._checked_grade(run, replay=given.a_replay_returning(replayed))  # pyright: ignore[reportPrivateUsage]

    assert grade.status == CVEStatus.MISSED
    assert outcome is replayed


async def test_an_unchecked_replay_is_printed_with_its_reason_and_attempt_causes(
    monkeypatch: pytest.MonkeyPatch,
):
    output = given.captured_console(monkeypatch)
    unchecked = ReplayOutcome(
        CreditCheck(frozenset(), unchecked=True),
        UncheckedReason.NO_ATTEMPT_DECIDED,
        (ReplayAttemptFailure.LAUNCH_FAILED,) * 3,
    )

    replay = given.a_replay_returning(unchecked)

    await cve_audit._checked_grade(given.a_detecting_run(), replay=replay)  # pyright: ignore[reportPrivateUsage]

    line = f"{TARGET.cve_id}: replay unchecked, no_attempt_decided (launch_failed x3)"
    assert line in output.getvalue()


@pytest.mark.parametrize(
    ("overrides", "chain_budget", "max_chain_steps", "timeout"),
    [
        (None, 3, 5, TOOL_CALL_TIMEOUT),
        (RunOverrides(None, None, None), 3, 5, TOOL_CALL_TIMEOUT),
        (RunOverrides(7, 9, 11), 7, 9, 11),
        (RunOverrides(None, 9, None), 3, 9, TOOL_CALL_TIMEOUT),
        (RunOverrides(7, None, None), 7, 5, TOOL_CALL_TIMEOUT),
    ],
)
async def test_a_forced_setting_wins_and_an_unset_one_keeps_the_launch_own(
    monkeypatch: pytest.MonkeyPatch,
    overrides: RunOverrides | None,
    chain_budget: int,
    max_chain_steps: int,
    timeout: int,
):
    given.captured_console(monkeypatch)
    seen = given.an_audit_reporting(monkeypatch)
    target = given.a_target_launching(Launch("x", [], chain_budget=3, max_chain_steps=5))

    await attempt_once(target, given.an_auditor(), SessionThrottles(), {}, overrides)

    [graph_input] = seen.graph_inputs
    assert (graph_input["chain_budget"], graph_input["max_chain_steps"]) == (
        chain_budget,
        max_chain_steps,
    )
    assert seen.timeouts == [timeout]


@pytest.mark.parametrize(
    ("overrides", "tools_filter"),
    [
        (None, TARGET.tools_filter),
        (RunOverrides(None, None, None), TARGET.tools_filter),
        (RunOverrides(None, None, None, audit_every_tool=True), None),
    ],
)
async def test_the_graph_audits_the_target_tools_filter_unless_every_tool_is_audited(
    monkeypatch: pytest.MonkeyPatch,
    overrides: RunOverrides | None,
    tools_filter: frozenset[str] | None,
):
    given.captured_console(monkeypatch)
    seen = given.an_audit_reporting(monkeypatch)

    await attempt_once(
        given.a_target_launching(), given.an_auditor(), SessionThrottles(), {}, overrides
    )

    assert seen.tools_filters == [tools_filter]


async def test_every_attempt_of_a_target_is_billed_to_it(monkeypatch: pytest.MonkeyPatch):
    given.captured_console(monkeypatch)
    given.an_audit_reporting(monkeypatch, given.a_report_billed(100, 10))
    target = given.a_target_launching()
    throttles = SessionThrottles()

    for _ in range(2):
        await attempt_once(target, given.an_auditor(), throttles, places={})

    billed = throttles.by_target[target.cve_id].total
    assert (billed.input_tokens, billed.output_tokens) == (200, 20)


async def test_a_throttled_attempt_is_not_audited_again(monkeypatch: pytest.MonkeyPatch):
    given.captured_console(monkeypatch)
    attempt = given.ScriptedAttempts[GradedAudit]([ThrottledAttempt()])

    grade = await graded_despite_missed_steps(TARGET, attempt)

    assert grade is None
    assert attempt.calls == 1


async def test_an_attempt_holding_a_throttled_step_is_thrown_away_before_any_grading(
    monkeypatch: pytest.MonkeyPatch,
):
    output = given.captured_console(monkeypatch)
    given.an_audit_reporting(monkeypatch, given.a_report_missing(MissCause.PROVIDER_THROTTLED))
    target = given.a_target_launching()

    outcome = await attempt_once(target, given.an_auditor(), SessionThrottles(), places={})

    assert isinstance(outcome, ThrottledAttempt)
    printed = " ".join(output.getvalue().split())
    assert f"{target.cve_id} run skipped: throttled by the model provider past every retry" in (
        printed
    )


async def test_an_attempt_throttled_and_refused_reads_as_throttled(
    monkeypatch: pytest.MonkeyPatch,
):
    given.captured_console(monkeypatch)
    report = given.a_report_missing(MissCause.PROVIDER_REFUSAL, MissCause.PROVIDER_THROTTLED)
    given.an_audit_reporting(monkeypatch, report)

    outcome = await attempt_once(
        given.a_target_launching(), given.an_auditor(), SessionThrottles(), places={}
    )

    assert isinstance(outcome, ThrottledAttempt)


async def test_each_attempt_audits_under_a_breaker_of_its_own(monkeypatch: pytest.MonkeyPatch):
    given.captured_console(monkeypatch)
    seen = given.an_audit_reporting(monkeypatch)
    target = given.a_target_launching()

    for _ in range(2):
        await attempt_once(target, given.an_auditor(), SessionThrottles(), {})

    first, second = seen.breakers
    assert first is not None and second is not None
    assert first is not second


async def test_a_run_skipped_on_a_holdout_run_prints_the_error_type_without_its_message(
    monkeypatch: pytest.MonkeyPatch,
):
    output = given.captured_console(monkeypatch)
    target = given.a_target_failing_to_launch(LaunchError("secret-nonce"))

    await attempt_once(target, given.an_auditor(TYPES_ONLY), SessionThrottles(), {})

    printed = output.getvalue()
    assert f"{target.cve_id} run skipped" in printed
    assert "LaunchError" in printed
    assert "secret-nonce" not in printed


async def test_a_run_skipped_on_the_acceptance_gate_prints_the_error_message(
    monkeypatch: pytest.MonkeyPatch,
):
    output = given.captured_console(monkeypatch)
    target = given.a_target_failing_to_launch(LaunchError("secret-nonce"))

    await attempt_once(target, given.an_auditor(), SessionThrottles(), {})

    assert f"{target.cve_id} run skipped: secret-nonce" in output.getvalue()


async def test_a_missed_step_on_a_holdout_run_prints_its_cause_without_the_provider_message(
    monkeypatch: pytest.MonkeyPatch,
):
    output = given.captured_console(monkeypatch)
    given.an_audit_reporting(monkeypatch, given.a_report_missing(MissCause.PROVIDER_REFUSAL))
    auditor = given.an_auditor(TYPES_ONLY)

    await attempt_once(given.a_target_launching(), auditor, SessionThrottles(), {})

    printed = output.getvalue()
    assert "Refused by the model provider" in printed
    assert "Invalid prompt" not in printed


_SHAPES = pytest.mark.parametrize("grouped", [True, False], ids=["grouped", "bare"])


@_SHAPES
async def test_a_server_failing_inside_the_graph_is_a_run_skipped(
    monkeypatch: pytest.MonkeyPatch, grouped: bool
):
    output = given.captured_console(monkeypatch)
    given.an_audit_raising(monkeypatch, TimeoutError("list_tools timed out"), grouped=grouped)

    outcome = await attempt_once(
        given.a_target_launching(), given.an_auditor(), SessionThrottles(), {}
    )

    assert outcome is None
    assert f"{TARGET.cve_id} run skipped" in output.getvalue()


@_SHAPES
async def test_a_fatal_provider_error_stops_the_run(monkeypatch: pytest.MonkeyPatch, grouped: bool):
    given.captured_console(monkeypatch)
    error = ModelAuthenticationError("invalid key")
    given.an_audit_raising(monkeypatch, error, grouped=grouped)

    with pytest.raises(ProviderFatal) as stopped:
        await attempt_once(given.a_target_launching(), given.an_auditor(), SessionThrottles(), {})

    assert stopped.value.cause is error


@_SHAPES
async def test_a_transient_provider_error_throws_the_attempt_away_naming_it_without_its_message(
    monkeypatch: pytest.MonkeyPatch, grouped: bool
):
    output = given.captured_console(monkeypatch)
    given.an_audit_raising(monkeypatch, ModelAPIError("secret-nonce"), grouped=grouped)

    outcome = await attempt_once(
        given.a_target_launching(), given.an_auditor(), SessionThrottles(), {}
    )

    assert isinstance(outcome, ProviderErrorAttempt)
    printed = output.getvalue()
    assert f"{TARGET.cve_id} run skipped" in printed
    assert "ModelAPIError" in printed
    assert "secret-nonce" not in printed


async def test_a_provider_error_attempt_is_not_audited_again(monkeypatch: pytest.MonkeyPatch):
    given.captured_console(monkeypatch)
    attempt = given.ScriptedAttempts[GradedAudit]([ProviderErrorAttempt("ModelAPIError")])

    grade = await graded_despite_missed_steps(TARGET, attempt)

    assert grade is None
    assert attempt.calls == 1
