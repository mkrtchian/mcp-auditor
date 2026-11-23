"""The retests of the cases that flipped against a confirmed baseline (ADR 025), kept as the
judge's answers so a wrong verdict reads apart from no verdict, and a throttled one apart from
both."""

import asyncio
from collections.abc import Awaitable, Callable
from dataclasses import dataclass

from evals.gate import CellOutcome, Observation, RetestRule
from evals.judge.baseline import JudgeBaseline
from evals.judge.fixture import JudgeCase
from evals.judge.gate import CaseRuns, compare_cases
from mcp_auditor.domain.models import EvalVerdict


@dataclass(frozen=True)
class JudgeCallVerdict:
    """`verdict` is None when the judge gave no verdict, `throttled` when that was because the
    model provider throttled the judgment past every retry."""

    verdict: EvalVerdict | None
    throttled: bool = False


type JudgeCall = Callable[[JudgeCase], Awaitable[JudgeCallVerdict]]
"""One judge call on one case. The session may call it concurrently."""


@dataclass(frozen=True)
class RetestContext:
    """`announce` hears the number of flipped cases about to be retested, when there are any."""

    judge: JudgeCall
    ground_truth: dict[str, EvalVerdict]
    declared: frozenset[str]
    cases: list[JudgeCase]
    announce: Callable[[int], None]


async def retest_flips(
    context: RetestContext, baseline: JudgeBaseline, runs: CaseRuns
) -> dict[str, list[JudgeCallVerdict]]:
    comparisons = compare_cases(baseline, runs, context.ground_truth, context.declared)
    flipped = [
        case
        for case in context.cases
        if case.id in comparisons and comparisons[case.id].outcome == CellOutcome.FLIP
    ]
    if flipped:
        context.announce(len(flipped))
    retested = await asyncio.gather(
        *(retest(context, case, baseline.retest_rule) for case in flipped)
    )
    return {case.id: answers for case, answers in zip(flipped, retested, strict=True)}


async def retest(
    context: RetestContext, case: JudgeCase, rule: RetestRule
) -> list[JudgeCallVerdict]:
    """One judge call at a time, until the retest rule decides. A call with no verdict
    reproduces the flip, as an uncovered retest does for the honeypots."""
    expected = context.ground_truth[case.id]
    answers: list[JudgeCallVerdict] = []
    observations: list[Observation] = []
    while rule.decide_retests(reproductions(observations, expected)) is None:
        answer = await context.judge(case)
        answers.append(answer)
        observations.append(Observation.of(answer.verdict))
    return answers


def reproductions(observations: list[Observation], expected: EvalVerdict) -> list[bool]:
    """What the retest rule and the gate read: whether each retest reproduced the flip."""
    return [observed != Observation.of(expected) for observed in observations]
