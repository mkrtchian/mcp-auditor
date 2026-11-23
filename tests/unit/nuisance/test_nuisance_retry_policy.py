import pytest
from langchain_core.exceptions import ModelAuthenticationError

import tests.unit.support.nuisance_holdout_runs as holdout_runs
from evals.cve.audit_attempts import INCOMPLETE_ATTEMPTS, ProviderErrorAttempt
from evals.cve.nuisance.audit import (
    NUISANCE_INFRA_ATTEMPTS,
    DroppedRun,
    LaunchFailed,
    NuisanceAudit,
    incomplete_causes,
    is_incomplete,
    nuisance_audit,
)
from evals.cve.nuisance.gate.gate_audit import gate_run
from evals.cve.nuisance.results import NotRunCause
from evals.cve.provider_errors import ProviderFatal
from mcp_auditor.domain.model_calls import MissedCallCause
from tests.unit.nuisance.support.test_nuisance_retry_policy_given import (
    PROVIDER_ERROR,
    ScriptedCalls,
)
from tests.unit.support.captured_console import CapturedOutput, a_captured_console
from tests.unit.support.nuisance_admissions import an_admitted_server

type Attempt = ScriptedCalls[NuisanceAudit | LaunchFailed | ProviderErrorAttempt]


@pytest.fixture(autouse=True)
def output(capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch) -> CapturedOutput:
    return a_captured_console(capsys, monkeypatch)


async def test_a_clean_report_stands_at_the_first_call():
    audit = holdout_runs.an_audit(False)
    attempt: Attempt = ScriptedCalls([audit])

    outcome = await nuisance_audit(an_admitted_server(), attempt)

    assert outcome is audit
    assert attempt.calls == 1


@pytest.mark.parametrize(
    "cause",
    [
        MissedCallCause.PROVIDER_REFUSAL,
        MissedCallCause.UNREADABLE_ANSWER,
        MissedCallCause.PROMPT_TOO_LONG,
    ],
)
async def test_an_incomplete_report_stands_without_a_retry(cause: MissedCallCause):
    audit = holdout_runs.an_audit(False, missed=cause)
    attempt: Attempt = ScriptedCalls([audit])

    outcome = await nuisance_audit(an_admitted_server(), attempt)

    assert outcome is audit
    assert attempt.calls == 1


@pytest.mark.parametrize(
    ("missed", "incomplete"),
    [
        (None, False),
        (MissedCallCause.PROVIDER_REFUSAL, True),
        (MissedCallCause.UNREADABLE_ANSWER, True),
        (MissedCallCause.PROMPT_TOO_LONG, True),
        (MissedCallCause.PROVIDER_THROTTLED, False),
    ],
)
def test_only_a_refused_unreadable_or_too_long_step_makes_a_report_incomplete(
    missed: MissedCallCause | None, incomplete: bool
):
    report = holdout_runs.a_report(False, missed=missed)

    assert is_incomplete(report) is incomplete
    assert incomplete_causes(report) == ({missed} if incomplete else set())


async def test_a_launch_failing_at_every_attempt_drops_the_run():
    attempt: Attempt = ScriptedCalls([LaunchFailed("no image")] * NUISANCE_INFRA_ATTEMPTS)

    outcome = await nuisance_audit(an_admitted_server(), attempt)

    assert outcome == DroppedRun(NotRunCause.LAUNCH_FAILURE)
    assert attempt.calls == NUISANCE_INFRA_ATTEMPTS


async def test_a_run_throttled_at_any_attempt_drops_as_throttled(output: CapturedOutput):
    throttled = holdout_runs.an_audit(False, missed=MissedCallCause.PROVIDER_THROTTLED)
    attempt: Attempt = ScriptedCalls([PROVIDER_ERROR, LaunchFailed("no image"), throttled])

    outcome = await nuisance_audit(an_admitted_server(), attempt)

    assert outcome == DroppedRun(NotRunCause.THROTTLED)
    assert attempt.calls == NUISANCE_INFRA_ATTEMPTS
    assert f"attempt 1/{NUISANCE_INFRA_ATTEMPTS}" in output.getvalue()


async def test_a_launch_failure_is_retried_and_a_later_report_stands():
    audit = holdout_runs.an_audit(False)
    attempt: Attempt = ScriptedCalls([LaunchFailed("no image"), audit])

    outcome = await nuisance_audit(an_admitted_server(), attempt)

    assert outcome is audit
    assert attempt.calls == 2


async def test_a_fatal_provider_error_of_an_attempt_stops_the_run_at_once():
    attempt: Attempt = ScriptedCalls([ProviderFatal(ModelAuthenticationError("invalid key"))])

    with pytest.raises(ProviderFatal):
        await nuisance_audit(an_admitted_server(), attempt)

    assert attempt.calls == 1


async def test_a_provider_error_at_every_attempt_drops_the_run_as_a_provider_error(
    output: CapturedOutput,
):
    attempt: Attempt = ScriptedCalls([PROVIDER_ERROR] * NUISANCE_INFRA_ATTEMPTS)

    outcome = await nuisance_audit(an_admitted_server(), attempt)

    assert outcome == DroppedRun(NotRunCause.PROVIDER_ERROR)
    assert attempt.calls == NUISANCE_INFRA_ATTEMPTS
    assert (
        f"provider error (ModelAPIError, status 500), attempt 1/{NUISANCE_INFRA_ATTEMPTS}"
        in output.getvalue()
    )


async def test_a_provider_error_is_retried_and_a_later_report_stands():
    audit = holdout_runs.an_audit(False)
    attempt: Attempt = ScriptedCalls([PROVIDER_ERROR, audit])

    outcome = await nuisance_audit(an_admitted_server(), attempt)

    assert outcome is audit


async def test_a_run_failing_on_a_provider_error_and_a_launch_drops_as_a_provider_error():
    no_image = LaunchFailed("no image")
    attempt: Attempt = ScriptedCalls([no_image, PROVIDER_ERROR, no_image])

    outcome = await nuisance_audit(an_admitted_server(), attempt)

    assert outcome == DroppedRun(NotRunCause.PROVIDER_ERROR)


async def test_a_gate_run_with_a_counted_alarm_stands_despite_a_refusal():
    audit = holdout_runs.an_audit(True, missed=MissedCallCause.PROVIDER_REFUSAL)
    audits = ScriptedCalls[NuisanceAudit | DroppedRun]([audit])

    run = await gate_run(holdout_runs.a_server(), audits)

    assert run is not None
    assert run.flagged
    assert run.report is audit.report
    assert audits.calls == 1


@pytest.mark.parametrize(
    "cause", [MissedCallCause.UNREADABLE_ANSWER, MissedCallCause.PROMPT_TOO_LONG]
)
async def test_a_gate_run_incomplete_without_an_alarm_is_attempted_again(
    cause: MissedCallCause, output: CapturedOutput
):
    incomplete = holdout_runs.an_audit(False, missed=cause)
    clean = holdout_runs.an_audit(False)
    audits = ScriptedCalls[NuisanceAudit | DroppedRun]([incomplete, clean])

    run = await gate_run(holdout_runs.a_server(), audits)

    assert run is not None
    assert not run.flagged
    assert run.report is clean.report
    assert audits.calls == 2
    assert f"attempt 1/{INCOMPLETE_ATTEMPTS}" in output.getvalue()
    assert "no counted alarm, attempted again" in output.getvalue()


async def test_a_gate_run_incomplete_at_every_attempt_does_not_complete(
    output: CapturedOutput,
):
    incomplete = holdout_runs.an_audit(False, missed=MissedCallCause.PROVIDER_REFUSAL)
    audits = ScriptedCalls[NuisanceAudit | DroppedRun]([incomplete] * INCOMPLETE_ATTEMPTS)

    run = await gate_run(holdout_runs.a_server(), audits)

    assert run is None
    assert audits.calls == INCOMPLETE_ATTEMPTS
    assert f"all {INCOMPLETE_ATTEMPTS} attempts" in output.getvalue()
    assert "run did not complete:" in output.getvalue()


async def test_a_dropped_gate_run_does_not_complete_at_once():
    audits = ScriptedCalls[NuisanceAudit | DroppedRun]([DroppedRun(NotRunCause.THROTTLED)])

    run = await gate_run(holdout_runs.a_server(), audits)

    assert run is None
    assert audits.calls == 1
