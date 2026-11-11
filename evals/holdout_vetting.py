"""The holdout pre-run check: drop from N, before any audit, a target dead on a version or one
the layout breaks or leaves unrouted.

A target the parallel pass would drop is vetted once more, alone, once every first pass has
finished, and runs if that second pass finds nothing. A fixture whose real software is slow or
nondeterministic (a local model that rarely miscopies a nonce, a call near the tool-call timeout
when the CPU is shared) can fail one pass while sound, and a broken fixture fails both."""

import asyncio
from collections.abc import Awaitable, Callable, Sequence
from dataclasses import dataclass

from evals.cve.detection.layout_check import LayoutCheck, layout_check, observe_versions
from evals.cve.detection.targets import LaunchMode, Target
from evals.cve.failure_text import FULL_DETAIL, ReportDetail
from evals.cve_places import Places, kept_records
from evals.holdout_results import NotRunCause, NotRunTarget


@dataclass(frozen=True)
class PreRunCheck:
    not_run: list[NotRunTarget]
    surviving: list[Target]
    second_pass: list[str]  # the targets that run only because their solo second pass was clean


async def vet_all(
    targets: Sequence[Target],
    check: Callable[[Target], Awaitable[list[str]]],
    layout: Callable[[Target], Awaitable[LayoutCheck]],
) -> PreRunCheck:
    first = await asyncio.gather(*(_vet(target, check, layout) for target in targets))
    final = [
        reason if reason is None else await _vet(target, check, layout)
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


async def _vet(
    target: Target,
    check: Callable[[Target], Awaitable[list[str]]],
    layout: Callable[[Target], Awaitable[LayoutCheck]],
) -> str | None:
    conditions = await check(target)
    observed = await layout(target)
    return vet_reason(target, conditions, observed)


def vet_reason(target: Target, conditions: list[str], layout: LayoutCheck) -> str | None:
    """Why a target is dropped from N before any audit, or None to run it. A break keeps a FALLBACK
    target but drops a NORMAL one calibrated under a launch it lost (holdout-rule.md, Deployment
    layout (A server the layout breaks))."""
    if conditions:
        return "dead on a version: " + "; ".join(conditions)
    if layout.gave_up is not None:
        return layout.gave_up
    if layout.breaks and target.launch_mode is LaunchMode.NORMAL:
        return "the layout breaks the server under the normal launch"
    if layout.unrouted:
        return "kept layout place(s) without a route: " + ", ".join(layout.unrouted)
    return None


async def observe_layout(
    target: Target, places: Places, *, report_detail: ReportDetail = FULL_DETAIL
) -> LayoutCheck:
    vuln, patched = await observe_versions(target, places, report_detail=report_detail)
    return layout_check(target, kept_records(target.kept_places, places), vuln, patched)
