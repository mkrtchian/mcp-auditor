from collections.abc import Sequence

from evals.cve.detection.calibration_check_exit import CalibrationCheckDeps
from evals.cve.detection.targets import Target
from evals.cve.places import Places


def deps_with(
    *,
    failures: Sequence[str] = (),
    all_pass: bool = True,
    raises: bool = False,
    checked: list[str] | None = None,
) -> CalibrationCheckDeps:
    """Layout and route checks reporting these failures and exploits reporting all_pass, or
    raising a fixture-config error. The flaw IDs whose exploits run are appended to checked."""

    async def check_layouts_and_routes(_targets: list[Target], _places: Places) -> list[str]:
        return list(failures)

    async def check_exploits(targets: list[Target], _places: Places) -> bool:
        if checked is not None:
            checked.extend(target.flaw_id for target in targets)
        if raises:
            raise ValueError("a kept id with no record")
        return all_pass

    return CalibrationCheckDeps(
        check_layouts_and_routes=check_layouts_and_routes, check_exploits=check_exploits
    )
