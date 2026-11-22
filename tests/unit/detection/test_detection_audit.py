import pytest

from evals.cve.audit_attempts import (
    INCOMPLETE_ATTEMPTS,
    AttemptOutcome,
    IncompleteAttempt,
    graded_despite_missed_model_calls,
    graded_or_incomplete,
)
from evals.cve.detection.audit import (
    RunOverrides,
    attempt_once,
    audit_target,
    checked_grade,
)
from evals.cve.detection.replay import ReplayAttemptFailure, ReplayOutcome, UncheckedReason
from evals.cve.detection.session_model import GradedAudit
from evals.cve.grammar import CreditCheck, MissKind, RunGrade, TargetStatus, grade_run
from evals.cve.proofs import UnitPlace
from evals.cve.report_units import units_of
from evals.cve.server_health import ServerHealth
from evals.metrics import SessionThrottles
from mcp_auditor.domain.models import MissCause
from tests.unit.cve.support import test_cve_grammar_given as grammar
from tests.unit.cve.support import test_cve_launch_audit_given as launch_given
from tests.unit.detection.support import test_detection_audit_given as given
from tests.unit.detection.support.detection_audits import (
    TARGET,
    ScriptedAttempts,
    a_report_missing,
    a_target_launching,
    an_auditor_reporting,
)
from tests.unit.detection.support.test_detection_oracle_given import a_detected_grade
from tests.unit.support.captured_console import a_captured_console

_REFUSED = frozenset({MissCause.PROVIDER_REFUSAL})


def test_a_misconfigured_model_fails_before_any_target_is_launched(
    monkeypatch: pytest.MonkeyPatch,
):
    monkeypatch.setenv("MCP_AUDITOR_PROVIDER", "no-such-provider")

    with pytest.raises(ValueError):
        audit_target(budget=10, throttles=SessionThrottles(), places={})


async def test_a_throttled_audit_is_reported_with_its_count(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
):
    output = a_captured_console(capsys, monkeypatch)
    auditor = an_auditor_reporting(given.a_report_throttled(2))

    await attempt_once(a_target_launching(), auditor, SessionThrottles(), {})

    line = f"{TARGET.flaw_id}: throttled 2 time(s) by the model provider (HTTP 429)"
    assert line in output.getvalue()


async def test_an_audit_never_throttled_says_nothing_of_throttling(
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
):
    output = a_captured_console(capsys, monkeypatch)
    auditor = an_auditor_reporting(given.a_report_throttled(0))

    await attempt_once(a_target_launching(), auditor, SessionThrottles(), {})

    assert "throttled" not in output.getvalue()


async def test_an_audit_carries_its_server_health_and_warns_of_a_lost_connection(
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
):
    output = a_captured_console(capsys, monkeypatch)
    auditor = given.an_audit_on_a_noisy_server(non_protocol_lines=2, lost_calls=1)

    outcome = await attempt_once(a_target_launching(), auditor, SessionThrottles(), {})

    assert isinstance(outcome, GradedAudit)
    assert outcome.health == ServerHealth(2, 1)
    assert f"{TARGET.flaw_id}: server connection lost on 1 call(s)" in output.getvalue()


async def test_an_audit_with_no_lost_connection_says_nothing_of_one(
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
):
    output = a_captured_console(capsys, monkeypatch)
    auditor = given.an_audit_on_a_noisy_server(non_protocol_lines=2, lost_calls=0)

    await attempt_once(a_target_launching(), auditor, SessionThrottles(), {})

    assert "connection lost" not in output.getvalue()


async def test_a_refused_audit_is_audited_again_and_graded_by_the_first_attempt_not_refused(
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
):
    a_captured_console(capsys, monkeypatch)
    graded = GradedAudit(a_detected_grade(), grammar.a_report(server_command="second attempt"))
    attempt = ScriptedAttempts([IncompleteAttempt(grammar.a_report(), _REFUSED), graded])

    outcome = await graded_despite_missed_model_calls(TARGET, attempt)

    assert outcome is graded
    assert attempt.calls == 2


async def test_an_audit_missing_a_step_at_every_attempt_is_a_run_not_completed(
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
):
    output = a_captured_console(capsys, monkeypatch)
    unreadable = IncompleteAttempt(grammar.a_report(), frozenset({MissCause.UNREADABLE_ANSWER}))
    outcomes: list[AttemptOutcome[GradedAudit]] = [
        IncompleteAttempt(grammar.a_report(), _REFUSED),
        *[unreadable] * (INCOMPLETE_ATTEMPTS - 1),
    ]
    attempt = ScriptedAttempts[GradedAudit](outcomes)

    grade = await graded_despite_missed_model_calls(TARGET, attempt)

    assert grade is None
    assert attempt.calls == INCOMPLETE_ATTEMPTS
    printed = " ".join(output.getvalue().split())
    assert f"{TARGET.flaw_id}: attempt 1/{INCOMPLETE_ATTEMPTS}: refused by the model provider" in (
        printed
    )
    assert f"{TARGET.flaw_id}: attempt 2/{INCOMPLETE_ATTEMPTS}: unreadable model answer" in printed
    assert f"{TARGET.flaw_id} run skipped" in printed
    assert "refused by the model provider and unreadable model answer" in printed


async def test_an_attempt_whose_prompt_was_too_long_names_its_cause(
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
):
    output = a_captured_console(capsys, monkeypatch)
    too_long = IncompleteAttempt(grammar.a_report(), frozenset({MissCause.PROMPT_TOO_LONG}))
    graded = GradedAudit(a_detected_grade(), grammar.a_report())
    attempt = ScriptedAttempts[GradedAudit]([too_long, graded])

    await graded_despite_missed_model_calls(TARGET, attempt)

    printed = " ".join(output.getvalue().split())
    assert (
        f"{TARGET.flaw_id}: attempt 1/{INCOMPLETE_ATTEMPTS}:"
        " prompt longer than the model's context window, not graded"
    ) in printed


async def test_a_run_skipped_on_launch_is_not_audited_again(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
):
    a_captured_console(capsys, monkeypatch)
    attempt = ScriptedAttempts[GradedAudit]([None])

    grade = await graded_despite_missed_model_calls(TARGET, attempt)

    assert grade is None
    assert attempt.calls == 1


@pytest.mark.parametrize("cause", list(MissCause))
def test_a_detection_is_kept_whatever_model_call_was_missed(cause: MissCause):
    outcome = graded_or_incomplete(a_detected_grade(), a_report_missing(cause))

    assert isinstance(outcome, RunGrade)
    assert outcome.status == TargetStatus.DETECTED


@pytest.mark.parametrize("cause", list(MissCause))
def test_a_miss_with_a_missed_model_call_is_not_graded_and_carries_its_cause(cause: MissCause):
    missed = grammar.a_missed_run(MissKind.AIMED_NO_PROOF)

    outcome = graded_or_incomplete(missed, a_report_missing(cause))

    assert isinstance(outcome, IncompleteAttempt)
    assert outcome.causes == {cause}


def test_a_miss_with_no_missed_model_call_is_graded_a_miss():
    missed = grammar.a_missed_run(MissKind.AIMED_NO_PROOF)

    outcome = graded_or_incomplete(missed, grammar.a_report())

    assert isinstance(outcome, RunGrade)
    assert outcome.status == TargetStatus.MISSED


def test_a_struck_only_credit_with_a_refused_model_call_reads_as_refused():
    # The replay struck the run's only credit, so the final grade is a miss. A refused model call
    # then makes it a refusal, not a genuine miss, so a refusal never poisons the gate or the
    # baseline.
    struck = RunGrade(
        status=TargetStatus.MISSED,
        miss_kind=MissKind.AIMED_NO_PROOF,
        struck_places=frozenset({grammar.PLACE}),
    )

    outcome = graded_or_incomplete(struck, a_report_missing(MissCause.PROVIDER_REFUSAL))

    assert isinstance(outcome, IncompleteAttempt)


async def test_a_non_detecting_run_is_graded_with_no_replay():
    run = given.a_run(grammar.a_report(cases=[grammar.a_case(verdict=grammar.PASS)]))

    grade, _ = await checked_grade(run, replay=given.a_replay_that_must_not_run)

    assert grade.status == grade_run(run.run_target, units_of(run.report)).status


async def test_a_detecting_run_is_regraded_on_the_credits_the_replay_strikes():
    run = given.a_detecting_run()
    struck = CreditCheck(frozenset({UnitPlace(0, grammar.PLACE)}), unchecked=False)
    replayed = ReplayOutcome(struck, unchecked_reason=None, attempt_failures=())

    grade, outcome = await checked_grade(run, replay=given.a_replay_returning(replayed))

    assert grade.status == TargetStatus.MISSED
    assert outcome is replayed


async def test_an_unchecked_replay_is_printed_with_its_reason_and_attempt_causes(
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
):
    output = a_captured_console(capsys, monkeypatch)
    unchecked = ReplayOutcome(
        CreditCheck(frozenset(), unchecked=True),
        UncheckedReason.NO_ATTEMPT_DECIDED,
        (ReplayAttemptFailure.LAUNCH_FAILED,) * 3,
    )

    replay = given.a_replay_returning(unchecked)

    await checked_grade(given.a_detecting_run(), replay=replay)

    line = f"{TARGET.flaw_id}: replay unchecked, no_attempt_decided (launch_failed x3)"
    assert line in output.getvalue()


async def test_the_run_overrides_reach_the_graph_and_the_client(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
):
    a_captured_console(capsys, monkeypatch)
    graphs = launch_given.graph_reporting([grammar.a_report()])
    connect = launch_given.FakeConnect()
    auditor = launch_given.an_auditor(graphs=graphs, connect=connect)

    await attempt_once(
        a_target_launching(), auditor, SessionThrottles(), {}, RunOverrides(7, 9, 11)
    )

    [graph_input] = graphs.graph_inputs
    assert (graph_input["chain_budget"], graph_input["max_chain_steps"]) == (7, 9)
    assert connect.timeouts == [11]


@pytest.mark.parametrize(
    ("overrides", "tools_filter"),
    [
        (None, TARGET.tools_filter),
        (RunOverrides(None, None, None), TARGET.tools_filter),
        (RunOverrides(None, None, None, audit_every_tool=True), None),
    ],
)
async def test_the_graph_audits_the_target_tools_filter_unless_every_tool_is_audited(
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
    overrides: RunOverrides | None,
    tools_filter: frozenset[str] | None,
):
    a_captured_console(capsys, monkeypatch)
    graphs = launch_given.graph_reporting([grammar.a_report()])
    auditor = launch_given.an_auditor(graphs=graphs)

    await attempt_once(a_target_launching(), auditor, SessionThrottles(), {}, overrides)

    assert graphs.tools_filters == [tools_filter]


async def test_every_attempt_of_a_target_is_billed_to_it(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
):
    a_captured_console(capsys, monkeypatch)
    auditor = an_auditor_reporting(*[given.a_report_billed(100, 10)] * 2)
    target = a_target_launching()
    throttles = SessionThrottles()

    for _ in range(2):
        await attempt_once(target, auditor, throttles, places={})

    billed = throttles.by_target[target.flaw_id].total
    assert (billed.input_tokens, billed.output_tokens) == (200, 20)
