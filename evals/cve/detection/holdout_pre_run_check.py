"""The pre-run check of a detection holdout run: drop from N, before any audit, a target out of
calibration or one the layout check fails (`layout_failure`).

A target the parallel pass would drop is checked once more, alone, once every first pass has
finished, and runs if that second pass finds nothing. A fixture whose real software is slow or
nondeterministic (a local model that rarely miscopies a nonce, a call near the tool-call timeout
when the CPU is shared) can fail one pass while sound, and a broken fixture fails both."""

import asyncio
from collections.abc import Awaitable, Callable, Sequence
from dataclasses import dataclass

from evals.cve.detection.holdout_results import NotRunCause, NotRunTarget
from evals.cve.detection.layout_check import (
    LayoutCheck,
    layout_failure,
)
from evals.cve.detection.targets import Target


@dataclass(frozen=True)
class PreRunCheck:
    not_run: list[NotRunTarget]
    surviving: list[Target]
    second_pass: list[str]  # the targets that run only because their solo second pass was clean


async def check_before_run(
    targets: Sequence[Target],
    check: Callable[[Target], Awaitable[list[str]]],
    layout: Callable[[Target], Awaitable[LayoutCheck]],
) -> PreRunCheck:
    first = await asyncio.gather(*(_check_one(target, check, layout) for target in targets))
    final = [
        reason if reason is None else await _check_one(target, check, layout)
        for target, reason in zip(targets, first, strict=True)
    ]
    paired = list(zip(targets, final, strict=True))
    return PreRunCheck(
        not_run=[
            NotRunTarget(t.flaw_id, r, NotRunCause.PRE_RUN_CHECK)
            for t, r in paired
            if r is not None
        ],
        surviving=[t for t, r in paired if r is None],
        second_pass=[
            target.flaw_id
            for target, before, after in zip(targets, first, final, strict=True)
            if before is not None and after is None
        ],
    )


async def _check_one(
    target: Target,
    check: Callable[[Target], Awaitable[list[str]]],
    layout: Callable[[Target], Awaitable[LayoutCheck]],
) -> str | None:
    reasons = await check(target)
    observed = await layout(target)
    return not_run_reason(target, reasons, observed)


def not_run_reason(target: Target, reasons: list[str], layout: LayoutCheck) -> str | None:
    """Why a target is dropped from N before any audit, or None to run it."""
    if reasons:
        return "out of calibration: " + "; ".join(reasons)
    return layout_failure(target, layout)
