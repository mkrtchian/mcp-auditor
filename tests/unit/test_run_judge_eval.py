from io import StringIO

from rich.console import Console
from rich.progress import Progress

import tests.unit.support.test_judge_session_given as given
from evals.run_judge_eval import JudgeCallTracking
from mcp_auditor.domain.ports import ProviderThrottled, ProviderUsage


async def test_a_judgment_throttled_past_every_retry_is_recorded_and_gives_no_verdict():
    [case, *_] = given.a_judge_fixture().cases
    usage = ProviderUsage(input_tokens=40, throttled_requests=5)
    llm = given.RaisingLLM(ProviderThrottled("429 Too Many Requests", 300.0, usage))
    progress = Progress(console=Console(file=StringIO()))
    tracking = JudgeCallTracking(llm, progress, run_calls=4)

    verdict = await tracking.judge(case)

    assert verdict is None
    assert tracking.throttled_cases == [case.id]
    assert tracking.throttles.requests == 5
    assert tracking.throttles.usage == usage
    assert progress.tasks[0].completed == 1
