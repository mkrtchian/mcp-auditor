from functools import cache

from evals.cve.census.census import CENSUS_PATH, load_census
from evals.cve.detection.holdout_targets import HOLDOUT_TARGETS
from evals.cve.detection.targets import Target
from evals.cve.nuisance.admission.admission import (
    ADMISSION_PATH,
    AdmittedServer,
    NuisanceAdmission,
)
from evals.cve.nuisance.admission.admission_load import load_admission
from evals.cve.nuisance.admission.re_admission_dossier import fix_check_modules
from evals.cve.nuisance.admission.walk_record import WalkInputs, load_walk_record
from evals.cve.nuisance.commands import WALK_RECORD_PATH


def a_committed_server_with_fix_checks() -> AdmittedServer:
    return next(server for server in the_committed_admission().servers if fix_check_modules(server))


def a_detection_holdout_server_with_its_own_fix_check() -> AdmittedServer:
    """An admitted server with a holdout target among its flaws whose fix check is its own, not
    a holdout calibration copy."""
    return next(
        server
        for server in the_committed_admission().servers
        if any(
            flaw.flaw in _holdout_identifiers()
            and flaw.fix_check.source != "detection_holdout_calibration"
            for flaw in server.flaws
        )
    )


def its_holdout_targets(server: AdmittedServer) -> list[Target]:
    flaws = {flaw.flaw for flaw in server.flaws}
    return [target for target in HOLDOUT_TARGETS if target.flaw_id in flaws]


@cache
def the_committed_admission() -> NuisanceAdmission:
    return load_admission(ADMISSION_PATH, the_committed_walk_inputs())


@cache
def the_committed_walk_inputs() -> WalkInputs:
    return load_walk_record(WALK_RECORD_PATH, load_census(CENSUS_PATH))


def _holdout_identifiers() -> set[str]:
    return {target.flaw_id for target in HOLDOUT_TARGETS}
