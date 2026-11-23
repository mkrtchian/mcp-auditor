import pytest

import tests.unit.support.grammar_inputs as grammar
import tests.unit.support.launch_audit_fakes as launch_audit_fakes
from evals.cve.detection.audit import (
    attempt_once,
    audit_target,
    checked_grade,
)
from evals.cve.detection.replay import ReplayAttemptFailure, ReplayOutcome, UncheckedReason
from evals.cve.detection.session_model import GradedAudit
from evals.cve.grammar import CreditCheck, TargetStatus, grade_run
from evals.cve.launch_audit import RunOverrides
from evals.cve.proofs import UnitPlace
from evals.cve.report_units import units_of
from evals.cve.server_health import ServerHealth
from evals.session_usage import SessionThrottles
from tests.unit.detection.support import test_detection_audit_given as given
from tests.unit.detection.support.detection_audits import (
    TARGET,
    a_target_launching,
    an_auditor_reporting,
)
from tests.unit.support.captured_console import a_captured_console


def test_a_misconfigured_model_fails_before_any_target_is_launched(
    monkeypatch: pytest.MonkeyPatch,
):
    monkeypatch.setenv("MCP_AUDITOR_PROVIDER", "no-such-provider")

    with pytest.raises(ValueError):
        audit_target(test_budget=10, throttles=SessionThrottles(), places={})


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
    graphs = launch_audit_fakes.graph_reporting([grammar.a_report()])
    connect = launch_audit_fakes.FakeConnect()
    auditor = launch_audit_fakes.an_auditor(graphs=graphs, connect=connect)

    await attempt_once(
        a_target_launching(), auditor, SessionThrottles(), {}, RunOverrides(7, 9, 11)
    )

    [graph_input] = graphs.graph_inputs
    assert (graph_input["chain_budget"], graph_input["max_chain_steps"]) == (7, 9)
    assert connect.timeouts == [11]


@pytest.mark.parametrize(
    ("overrides", "tools_filter"),
    [
        (RunOverrides(), TARGET.tools_filter),
        (RunOverrides(audit_every_tool=True), None),
    ],
)
async def test_the_graph_audits_the_target_tools_filter_unless_every_tool_is_audited(
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
    overrides: RunOverrides,
    tools_filter: frozenset[str] | None,
):
    a_captured_console(capsys, monkeypatch)
    graphs = launch_audit_fakes.graph_reporting([grammar.a_report()])
    auditor = launch_audit_fakes.an_auditor(graphs=graphs)

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
