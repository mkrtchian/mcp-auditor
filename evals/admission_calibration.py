"""The exit rule of a CVE admission calibration, shared by the benchmark's --calibrate and the
holdout's calibrate: 0 when every target is live and every admission check passed, else 1.
Container hygiene stays with each command, which already owns it."""

from collections.abc import Awaitable, Callable
from dataclasses import dataclass

from evals.concurrency import bounded
from evals.cve_calibration import calibrate_all, calibrate_one
from evals.cve_layout_check import confirm_admission
from evals.cve_places import Places
from evals.cve_targets import CVETarget


@dataclass(frozen=True)
class CalibrationDeps:
    confirm_admission: Callable[[list[CVETarget], Places], Awaitable[list[str]]]
    calibrate_all: Callable[[list[CVETarget], Places], Awaitable[bool]]


async def calibrate_admitted(
    targets: list[CVETarget], places: Places, deps: CalibrationDeps
) -> int:
    # ADR 031 admission: the rule runs the layout check before the exploits (holdout-rule.md,
    # Deployment layout (A server the layout breaks)), so it reports its break first.
    admission_failures = await deps.confirm_admission(targets, places)
    all_live = await deps.calibrate_all(targets, places)
    return 0 if all_live and not admission_failures else 1


def default_calibration_deps(concurrency: int, ci: bool) -> CalibrationDeps:
    async def admission(targets: list[CVETarget], places: Places) -> list[str]:
        return await confirm_admission(targets, places, ci=ci)

    async def calibration(targets: list[CVETarget], places: Places) -> bool:
        return await calibrate_all(
            targets, bounded(lambda target: calibrate_one(target, places), concurrency), ci=ci
        )

    return CalibrationDeps(confirm_admission=admission, calibrate_all=calibration)
