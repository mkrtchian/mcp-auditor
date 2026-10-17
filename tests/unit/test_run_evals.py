import tests.unit.support.test_eval_replay_given as replay_given
import tests.unit.support.test_run_evals_given as given
from evals.eval_runs import run_all
from evals.gate import ReplayRule
from evals.metrics import SessionThrottles
from evals.replay import Replayer
from evals.run_evals import counted_audit, replay_audit
from mcp_auditor.domain.models import MissCause


async def test_a_pass_holding_a_throttled_step_is_a_failed_pass_its_429s_counted():
    throttles = SessionThrottles()
    fake = given.FakeHoneypotAudit("subtle", MissCause.PROVIDER_THROTTLED, throttled_requests=7)

    outcome = await run_all(counted_audit(fake, throttles), runs=1)

    assert outcome.details == []
    assert throttles.requests == 7


async def test_a_pass_holding_a_refused_step_still_completes():
    fake = given.FakeHoneypotAudit("subtle", MissCause.PROVIDER_REFUSAL)

    outcome = await run_all(counted_audit(fake, SessionThrottles()), runs=1)

    assert len(outcome.details) == 1


async def test_a_replay_holding_a_throttled_step_is_a_failed_replay():
    fake = given.FakeHoneypotAudit("alpha", MissCause.PROVIDER_THROTTLED)
    replayer = Replayer(
        audit=replay_audit(counted_audit(fake, SessionThrottles())),
        honeypots=replay_given.HONEYPOTS,
        announce=lambda _: None,
        warn=lambda _: None,
    )

    _, failures = await replayer.settle_flips(
        replay_given.cells_flipping(replay_given.ALPHA_CELL), ReplayRule()
    )

    assert failures == ["a replay of alpha failed"]
