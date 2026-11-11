from io import StringIO

import pytest
from langchain_core.exceptions import ModelAuthenticationError

import tests.unit.support.test_eval_display_given as display_given
from evals import nuisance_audit as nuisance_audit_module
from evals.cve import launch_audit
from evals.cve.audit_attempts import INCOMPLETE_ATTEMPTS
from evals.cve.provider_errors import ProviderFatal
from evals.nuisance_audit import (
    NUISANCE_INFRA_ATTEMPTS,
    DroppedRun,
    LaunchFailed,
    NuisanceAudit,
    ProviderError,
    gate_run,
    is_incomplete,
    nuisance_audit,
)
from evals.nuisance_results import NotRunCause
from mcp_auditor.domain.models import MissCause
from tests.unit.support import test_nuisance_run_given as run_given
from tests.unit.support.test_nuisance_admission_given import an_admitted_server
from tests.unit.support.test_nuisance_retry_policy_given import PROVIDER_ERROR, ScriptedCalls

type Attempt = ScriptedCalls[NuisanceAudit | LaunchFailed | ProviderError]


@pytest.fixture(autouse=True)
def output(monkeypatch: pytest.MonkeyPatch) -> StringIO:
    return display_given.a_captured_console(monkeypatch, nuisance_audit_module, launch_audit)


async def test_a_clean_report_stands_at_the_first_call():
    audit = run_given.an_audit(False)
    attempt: Attempt = ScriptedCalls([audit])

    outcome = await nuisance_audit(an_admitted_server(), attempt)

    assert outcome is audit
    assert attempt.calls == 1


@pytest.mark.parametrize("cause", [MissCause.PROVIDER_REFUSAL, MissCause.UNREADABLE_ANSWER])
async def test_an_incomplete_report_stands_without_a_retry(cause: MissCause):
    audit = run_given.an_audit(False, missed=cause)
    attempt: Attempt = ScriptedCalls([audit])

    outcome = await nuisance_audit(an_admitted_server(), attempt)

    assert outcome is audit
    assert attempt.calls == 1


@pytest.mark.parametrize(
    ("missed", "incomplete"),
    [
        (None, False),
        (MissCause.PROVIDER_REFUSAL, True),
        (MissCause.UNREADABLE_ANSWER, True),
        (MissCause.PROVIDER_THROTTLED, False),
    ],
)
def test_only_a_refused_or_unreadable_step_makes_a_report_incomplete(
    missed: MissCause | None, incomplete: bool
):
    assert is_incomplete(run_given.a_report(False, missed=missed)) is incomplete


async def test_a_launch_failing_at_every_attempt_drops_the_run():
    attempt: Attempt = ScriptedCalls([LaunchFailed("no image")] * NUISANCE_INFRA_ATTEMPTS)

    outcome = await nuisance_audit(an_admitted_server(), attempt)

    assert outcome == DroppedRun(NotRunCause.LAUNCH_FAILURE)
    assert attempt.calls == NUISANCE_INFRA_ATTEMPTS


async def test_a_run_throttled_at_any_attempt_drops_as_throttled(output: StringIO):
    throttled = run_given.an_audit(False, missed=MissCause.PROVIDER_THROTTLED)
    attempt: Attempt = ScriptedCalls([PROVIDER_ERROR, LaunchFailed("no image"), throttled])

    outcome = await nuisance_audit(an_admitted_server(), attempt)

    assert outcome == DroppedRun(NotRunCause.THROTTLED)
    assert attempt.calls == NUISANCE_INFRA_ATTEMPTS
    assert f"attempt 1/{NUISANCE_INFRA_ATTEMPTS}" in output.getvalue()


async def test_a_launch_failure_is_retried_and_a_later_report_stands():
    audit = run_given.an_audit(False)
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
    output: StringIO,
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
    audit = run_given.an_audit(False)
    attempt: Attempt = ScriptedCalls([PROVIDER_ERROR, audit])

    outcome = await nuisance_audit(an_admitted_server(), attempt)

    assert outcome is audit


async def test_a_run_failing_on_a_provider_error_and_a_launch_drops_as_a_provider_error():
    no_image = LaunchFailed("no image")
    attempt: Attempt = ScriptedCalls([no_image, PROVIDER_ERROR, no_image])

    outcome = await nuisance_audit(an_admitted_server(), attempt)

    assert outcome == DroppedRun(NotRunCause.PROVIDER_ERROR)


async def test_a_gate_run_with_a_counted_alarm_stands_despite_a_refused_step():
    audit = run_given.an_audit(True, missed=MissCause.PROVIDER_REFUSAL)
    audits = ScriptedCalls[NuisanceAudit | DroppedRun]([audit])

    run = await gate_run(run_given.a_server(), audits)

    assert run is not None
    assert run.flagged
    assert run.report is audit.report
    assert audits.calls == 1


async def test_a_gate_run_incomplete_without_an_alarm_is_attempted_again(
    output: StringIO,
):
    unreadable = run_given.an_audit(False, missed=MissCause.UNREADABLE_ANSWER)
    clean = run_given.an_audit(False)
    audits = ScriptedCalls[NuisanceAudit | DroppedRun]([unreadable, clean])

    run = await gate_run(run_given.a_server(), audits)

    assert run is not None
    assert not run.flagged
    assert run.report is clean.report
    assert audits.calls == 2
    assert f"attempt 1/{INCOMPLETE_ATTEMPTS}" in output.getvalue()


async def test_a_gate_run_incomplete_at_every_attempt_does_not_complete(
    output: StringIO,
):
    incomplete = run_given.an_audit(False, missed=MissCause.PROVIDER_REFUSAL)
    audits = ScriptedCalls[NuisanceAudit | DroppedRun]([incomplete] * INCOMPLETE_ATTEMPTS)

    run = await gate_run(run_given.a_server(), audits)

    assert run is None
    assert audits.calls == INCOMPLETE_ATTEMPTS
    assert f"all {INCOMPLETE_ATTEMPTS} attempts" in output.getvalue()


async def test_a_dropped_gate_run_does_not_complete_at_once():
    audits = ScriptedCalls[NuisanceAudit | DroppedRun]([DroppedRun(NotRunCause.THROTTLED)])

    run = await gate_run(run_given.a_server(), audits)

    assert run is None
    assert audits.calls == 1
