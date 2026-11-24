import pytest
from langchain_core.exceptions import ModelAPIError, ModelAuthenticationError

import tests.unit.evals.support.test_run_honeypot_suite_given as given
from evals.gate import RetestRule
from evals.honeypot.retest import Retester
from evals.honeypot.runs import run_all
from evals.run_honeypot_suite import counted_audit, exit_code_of, parse_args, retest_audit
from evals.session_usage import SessionThrottles
from mcp_auditor.domain.model_calls import MissedCallCause
from tests.unit.evals.support import fictional_honeypots


async def test_a_pass_holding_a_throttled_model_call_is_a_failed_pass_its_429s_counted():
    throttles = SessionThrottles()
    fake = given.FakeHoneypotAudit(
        "subtle", MissedCallCause.PROVIDER_THROTTLED, throttled_requests=7
    )

    outcome = await run_all(counted_audit(fake, throttles), runs=1)

    assert outcome.details == []
    assert throttles.requests == 7


async def test_a_pass_holding_a_refusal_still_completes():
    fake = given.FakeHoneypotAudit("subtle", MissedCallCause.PROVIDER_REFUSAL)

    outcome = await run_all(counted_audit(fake, SessionThrottles()), runs=1)

    assert len(outcome.details) == 1


async def test_a_retest_holding_a_throttled_model_call_is_a_failed_retest():
    fake = given.FakeHoneypotAudit("alpha", MissedCallCause.PROVIDER_THROTTLED)
    retester = Retester(
        audit=retest_audit(counted_audit(fake, SessionThrottles())),
        honeypots=fictional_honeypots.HONEYPOTS,
        announce=lambda _: None,
        warn=lambda _: None,
    )

    _, failures = await retester.retest_flips(
        fictional_honeypots.cells_flipping(fictional_honeypots.ALPHA_CELL), RetestRule()
    )

    assert failures == ["a retest of alpha failed"]


def test_a_fatal_model_provider_error_stops_the_suite_with_its_traceback(
    capsys: pytest.CaptureFixture[str],
):
    error = ModelAuthenticationError("the API key was revoked")

    code = exit_code_of(given.a_suite_running(given.an_audit_raising(error), runs=2))

    output = capsys.readouterr()
    assert code == 4
    assert "failed" not in output.out
    assert "ModelAuthenticationError: the API key was revoked" in output.err


def test_a_fatal_status_on_the_error_raised_from_stops_the_suite_with_both_errors(
    capsys: pytest.CaptureFixture[str],
):
    error = given.an_error_caused_by_a_forbidden_status()

    code = exit_code_of(given.a_suite_running(given.an_audit_raising(error), runs=1))

    output = capsys.readouterr()
    assert code == 4
    assert "Error calling model 'gemini'" in output.err
    assert "key lacks access" in output.err


async def test_a_transient_model_provider_error_is_a_failed_run(capsys: pytest.CaptureFixture[str]):
    audit = given.an_audit_raising(ModelAPIError("overloaded"))

    outcome = await run_all(counted_audit(audit, SessionThrottles()), runs=1)

    assert outcome.details == []
    assert "Warning: run 1/1 failed:" in capsys.readouterr().out


async def test_a_fatal_model_provider_error_in_a_retest_stops_the_retests():
    error = ModelAuthenticationError("the API key was revoked")
    announced: list[str] = []
    retester = Retester(
        audit=retest_audit(counted_audit(given.an_audit_raising(error), SessionThrottles())),
        honeypots=fictional_honeypots.HONEYPOTS,
        announce=announced.append,
        warn=lambda _: None,
    )

    with pytest.raises(ModelAuthenticationError):
        await retester.retest_flips(
            fictional_honeypots.cells_flipping(fictional_honeypots.ALPHA_CELL), RetestRule()
        )

    assert not [message for message in announced if message.startswith("Warning")]


def test_the_no_baseline_flag_is_read():
    assert parse_args(["--no-baseline"]).no_baseline
