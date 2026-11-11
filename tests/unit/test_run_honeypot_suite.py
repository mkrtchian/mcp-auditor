import pytest

import tests.unit.support.test_honeypot_retest_given as retest_given
import tests.unit.support.test_run_honeypot_suite_given as given
from evals.gate import RetestRule
from evals.honeypot.retest import Retester
from evals.honeypot.runs import run_all, tracing_enabled
from evals.metrics import SessionThrottles
from evals.run_honeypot_suite import counted_audit, parse_args, retest_audit
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


async def test_a_retest_holding_a_throttled_step_is_a_failed_retest():
    fake = given.FakeHoneypotAudit("alpha", MissCause.PROVIDER_THROTTLED)
    retester = Retester(
        audit=retest_audit(counted_audit(fake, SessionThrottles())),
        honeypots=retest_given.HONEYPOTS,
        announce=lambda _: None,
        warn=lambda _: None,
    )

    _, failures = await retester.retest_flips(
        retest_given.cells_flipping(retest_given.ALPHA_CELL), RetestRule()
    )

    assert failures == ["a retest of alpha failed"]


@pytest.mark.parametrize(
    "value, expected",
    [
        ("true", True),
        ("True", True),
        ("1", True),
        ("yes", True),
        ("on", True),
        (" TRUE ", True),
        ("false", False),
        ("0", False),
        ("no", False),
        ("", False),
    ],
)
def test_tracing_enabled_parses_the_flag(
    monkeypatch: pytest.MonkeyPatch, value: str, expected: bool
) -> None:
    monkeypatch.delenv("LANGCHAIN_TRACING_V2", raising=False)
    monkeypatch.setenv("LANGSMITH_TRACING", value)
    assert tracing_enabled() is expected


def test_tracing_enabled_is_false_when_unset(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("LANGSMITH_TRACING", raising=False)
    monkeypatch.delenv("LANGCHAIN_TRACING_V2", raising=False)
    assert tracing_enabled() is False


def test_tracing_enabled_reads_langchain_v2(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("LANGSMITH_TRACING", raising=False)
    monkeypatch.setenv("LANGCHAIN_TRACING_V2", "true")
    assert tracing_enabled() is True


def test_no_baseline_runs_on_the_floors_alone(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr("sys.argv", ["run_honeypot_suite", "--no-baseline"])

    assert parse_args().no_baseline


def test_the_old_ungated_flag_is_refused(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr("sys.argv", ["run_honeypot_suite", "--ungated"])

    with pytest.raises(SystemExit) as refused:
        parse_args()

    assert refused.value.code == 2
