from io import StringIO

import pytest
from rich.console import Console
from rich.progress import Progress

import tests.unit.support.test_run_judge_eval_given as given
from evals.run_judge_eval import JudgeCallTracking, judge_one_case
from mcp_auditor.domain.models import EvalVerdict
from mcp_auditor.domain.ports import (
    ProviderRefusal,
    ProviderThrottled,
    ProviderUsage,
    UnparseableOutput,
)
from tests.fakes import RaisingLLM

THROTTLED = ProviderUsage(throttled_requests=1)


async def test_a_judgment_throttled_past_every_retry_is_recorded_and_gives_no_verdict():
    case = given.a_judge_case()
    usage = ProviderUsage(input_tokens=40, throttled_requests=5)
    llm = RaisingLLM(ProviderThrottled("429 Too Many Requests", 300.0, usage))
    progress = Progress(console=Console(file=StringIO()))
    tracking = JudgeCallTracking(llm, progress, run_calls=4)

    verdict = await tracking.judge(case)

    assert verdict is None
    assert tracking.throttled_cases == [case.id]
    assert tracking.throttles.requests == 5
    assert tracking.throttles.usage == usage
    assert progress.tasks[0].completed == 1


async def test_a_judge_call_returns_its_verdict_and_its_usage():
    usage = ProviderUsage(input_tokens=120, throttled_requests=2)
    llm = given.AnsweringLLM(EvalVerdict.FAIL, usage)

    assert await judge_one_case(llm, given.a_judge_case()) == (EvalVerdict.FAIL, usage)


@pytest.mark.parametrize(
    "error",
    [
        UnparseableOutput(attempts=3, truncated_attempts=0, usage=THROTTLED),
        ProviderRefusal("blocked by policy", THROTTLED),
    ],
)
async def test_a_judge_call_that_fails_to_answer_is_uncovered_and_keeps_its_usage(
    error: Exception,
):
    assert await judge_one_case(RaisingLLM(error), given.a_judge_case()) == (None, THROTTLED)


async def test_any_other_judge_call_failure_propagates():
    with pytest.raises(ConnectionError):
        await judge_one_case(RaisingLLM(ConnectionError("network down")), given.a_judge_case())
