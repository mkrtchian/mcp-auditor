"""The replays of the cases that flipped against a confirmed baseline (ADR 025), kept as
observations so a wrong verdict reads apart from no verdict."""

import asyncio
from collections.abc import Awaitable, Callable
from dataclasses import dataclass

from evals.gate import CellOutcome, Observation, ReplayRule
from evals.judge_baseline import JudgeBaseline
from evals.judge_fixture import JudgeCase
from evals.judge_gate import CaseRuns, compare_cases, observe_case
from mcp_auditor.domain.models import EvalVerdict

type JudgeCall = Callable[[JudgeCase], Awaitable[EvalVerdict | None]]
"""One judge call on one case, None when the judge gave no verdict. The session may call it
concurrently."""


@dataclass(frozen=True)
class ReplayContext:
    """`announce` hears the number of flipped cases about to be replayed, when there are any."""

    judge: JudgeCall
    ground_truth: dict[str, EvalVerdict]
    declared: frozenset[str]
    cases: list[JudgeCase]
    announce: Callable[[int], None]


async def replay_flips(
    context: ReplayContext, baseline: JudgeBaseline, runs: CaseRuns
) -> dict[str, list[Observation]]:
    comparisons = compare_cases(baseline, runs, context.ground_truth, context.declared)
    flipped = [
        case
        for case in context.cases
        if case.id in comparisons and comparisons[case.id].outcome == CellOutcome.FLIP
    ]
    if flipped:
        context.announce(len(flipped))
    replayed = await asyncio.gather(
        *(replay(context, case, baseline.replay_rule) for case in flipped)
    )
    return {case.id: observations for case, observations in zip(flipped, replayed, strict=True)}


async def replay(context: ReplayContext, case: JudgeCase, rule: ReplayRule) -> list[Observation]:
    """One judge call at a time, until the replay rule decides. A call with no verdict
    reproduces the flip, as an uncovered replay does for the honeypots."""
    expected = context.ground_truth[case.id]
    observations: list[Observation] = []
    while rule.decide_replays(reproductions(observations, expected)) is None:
        observations.append(observe_case(await context.judge(case)))
    return observations


def reproductions(observations: list[Observation], expected: EvalVerdict) -> list[bool]:
    """What the replay rule and the gate read: whether each replay reproduced the flip."""
    return [observed != Observation(expected.value) for observed in observations]
