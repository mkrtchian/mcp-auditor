from collections.abc import Sequence

from evals.admission_calibration import CalibrationDeps
from evals.cve_places import Places
from evals.cve_targets import CVETarget


def deps_with(
    *, failures: Sequence[str] = (), all_live: bool = True, raises: bool = False
) -> CalibrationDeps:
    """An admission reporting these failures and a calibration reporting all_live, or raising a
    fixture-config error."""

    async def confirm_admission(_targets: list[CVETarget], _places: Places) -> list[str]:
        return list(failures)

    async def calibrate_all(_targets: list[CVETarget], _places: Places) -> bool:
        if raises:
            raise ValueError("a kept id with no record")
        return all_live

    return CalibrationDeps(confirm_admission=confirm_admission, calibrate_all=calibrate_all)
