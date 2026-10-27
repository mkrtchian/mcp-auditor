"""The holdout pre-run check: drop from N, before any audit, a target dead on a version or one
the layout breaks or leaves unrouted."""

import asyncio
from collections.abc import Awaitable, Callable, Sequence

from evals.cve_layout_check import LayoutCheck, layout_check, observe_versions
from evals.cve_places import Places, kept_records
from evals.cve_targets import CVETarget, LaunchMode
from evals.holdout_results import NotRunCause, NotRunTarget


async def vet_all(
    targets: Sequence[CVETarget],
    check: Callable[[CVETarget], Awaitable[list[str]]],
    layout: Callable[[CVETarget], Awaitable[LayoutCheck]],
) -> tuple[list[NotRunTarget], list[CVETarget]]:
    reasons = await asyncio.gather(*(_vet(target, check, layout) for target in targets))
    paired = list(zip(targets, reasons, strict=True))
    not_run = [
        NotRunTarget(t.cve_id, r, NotRunCause.PRE_RUN_CHECK) for t, r in paired if r is not None
    ]
    surviving = [t for t, r in paired if r is None]
    return not_run, surviving


async def _vet(
    target: CVETarget,
    check: Callable[[CVETarget], Awaitable[list[str]]],
    layout: Callable[[CVETarget], Awaitable[LayoutCheck]],
) -> str | None:
    conditions = await check(target)
    observed = await layout(target)
    return vet_reason(target, conditions, observed)


def vet_reason(target: CVETarget, conditions: list[str], layout: LayoutCheck) -> str | None:
    """Why a target is dropped from N before any audit, or None to run it. A break keeps a FALLBACK
    target but drops a NORMAL one calibrated under a launch it lost (holdout-rule.md:159)."""
    if conditions:
        return "dead on a version: " + "; ".join(conditions)
    if layout.gave_up is not None:
        return layout.gave_up
    if layout.breaks and target.launch_mode is LaunchMode.NORMAL:
        return "the layout breaks the server under the normal launch"
    if layout.unrouted:
        return "kept layout place(s) without a route: " + ", ".join(layout.unrouted)
    return None


async def observe_layout(target: CVETarget, places: Places) -> LayoutCheck:
    vuln, patched = await observe_versions(target, places)
    return layout_check(target, kept_records(target.kept_places, places), vuln, patched)
