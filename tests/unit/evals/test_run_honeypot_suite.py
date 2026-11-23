import tests.unit.evals.support.test_run_honeypot_suite_given as given
from evals.gate import RetestRule
from evals.honeypot.retest import Retester
from evals.honeypot.runs import run_all
from evals.run_honeypot_suite import counted_audit, parse_args, retest_audit
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


def test_the_no_baseline_flag_is_read():
    assert parse_args(["--no-baseline"]).no_baseline
