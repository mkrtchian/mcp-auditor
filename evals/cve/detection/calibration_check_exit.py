"""The exit rule of the calibration check, shared by the acceptance targets' and the holdout
targets' commands: 0 when every target is live and fixed and every layout and route check passed,
else 1. Container hygiene stays with each command, which already owns it."""

from collections.abc import Awaitable, Callable
from dataclasses import dataclass

from evals.concurrency import bounded
from evals.cve.detection.calibration_check import check_calibrations, passes_calibration_check
from evals.cve.detection.layout_check import check_layouts_and_routes
from evals.cve.detection.targets import Target
from evals.cve.places import Places


@dataclass(frozen=True)
class CalibrationCheckDeps:
    check_layouts_and_routes: Callable[[list[Target], Places], Awaitable[list[str]]]
    check_exploits: Callable[[list[Target], Places], Awaitable[bool]]


async def run_calibration_check(
    targets: list[Target], places: Places, deps: CalibrationCheckDeps
) -> int:
    # ADR 031: the rule runs the layout check before the exploits (detection-suite-rule.md,
    # Deployment layout (A server the layout breaks)), so it reports its break first.
    layout_and_route_failures = await deps.check_layouts_and_routes(targets, places)
    all_pass = await deps.check_exploits(targets, places)
    return 0 if all_pass and not layout_and_route_failures else 1


def default_calibration_check_deps(concurrency: int, ci: bool) -> CalibrationCheckDeps:
    async def layouts_and_routes(targets: list[Target], places: Places) -> list[str]:
        return await check_layouts_and_routes(targets, places, ci=ci)

    async def exploits(targets: list[Target], places: Places) -> bool:
        return await check_calibrations(
            targets,
            bounded(lambda target: passes_calibration_check(target, places), concurrency),
            ci=ci,
        )

    return CalibrationCheckDeps(
        check_layouts_and_routes=layouts_and_routes, check_exploits=exploits
    )
