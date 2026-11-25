from evals.cve.detection.holdout_targets import HOLDOUT_TARGETS
from evals.cve.detection.targets import Target
from evals.cve.nuisance.admission.admission import AdmittedServer
from evals.cve.nuisance.admission.re_admission_dossier import fix_check_modules
from tests.unit.support.committed_nuisance_admission import the_committed_admission


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


def _holdout_identifiers() -> set[str]:
    return {target.flaw_id for target in HOLDOUT_TARGETS}
