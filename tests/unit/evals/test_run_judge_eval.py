from io import StringIO

import pytest
from rich.console import Console
from rich.progress import Progress

from evals.judge.retest import JudgeCallVerdict
from evals.run_judge_eval import JudgeCallTracking, judge_one_case, parse_args
from mcp_auditor.domain.models import EvalVerdict, Judgment, Severity
from mcp_auditor.domain.ports import (
    ProviderRefusal,
    ProviderThrottled,
    ProviderUsage,
    UnreadableAnswer,
)
from tests.fakes import FakeLLM, RaisingLLM
from tests.unit.evals.support.judge_baselines import PASS_CASE

THROTTLED = ProviderUsage(throttled_requests=1)


async def test_a_judgment_throttled_past_every_retry_says_so_and_gives_no_verdict():
    usage = ProviderUsage(input_tokens=40, throttled_requests=5)
    llm = RaisingLLM(ProviderThrottled("429 Too Many Requests", 300.0, usage))
    progress = Progress(console=Console(file=StringIO()))
    tracking = JudgeCallTracking(llm, progress, run_calls=4)

    assert await tracking.judge(PASS_CASE) == JudgeCallVerdict(None, throttled=True)
    assert tracking.throttles.requests == 5
    assert tracking.throttles.usage == usage
    assert progress.tasks[0].completed == 1


async def test_a_judge_call_returns_its_verdict_and_its_usage():
    usage = ProviderUsage(input_tokens=120, throttled_requests=2)
    judgment = Judgment(verdict=EvalVerdict.FAIL, justification="judged", severity=Severity.LOW)
    llm = FakeLLM([judgment], billing=lambda *_: usage)

    assert await judge_one_case(llm, PASS_CASE) == (EvalVerdict.FAIL, usage)


@pytest.mark.parametrize(
    "error",
    [
        UnreadableAnswer(parse_attempts=3, truncated_parse_attempts=0, usage=THROTTLED),
        ProviderRefusal("blocked by policy", THROTTLED),
    ],
)
async def test_a_judge_call_that_fails_to_answer_is_uncovered_and_keeps_its_usage(
    error: Exception,
):
    assert await judge_one_case(RaisingLLM(error), PASS_CASE) == (None, THROTTLED)


async def test_any_other_judge_call_failure_propagates():
    with pytest.raises(ConnectionError):
        await judge_one_case(RaisingLLM(ConnectionError("network down")), PASS_CASE)


def test_the_no_baseline_flag_is_read():
    assert parse_args(["--no-baseline"]).no_baseline
