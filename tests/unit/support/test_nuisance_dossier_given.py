from pathlib import Path

import tests.unit.support.test_census_figures_given as figures
import tests.unit.support.test_census_given as census_given
import tests.unit.support.test_nuisance_walk_given as walk_given
from evals.cve.detection.holdout_targets import HOLDOUT_TARGETS
from evals.cve.detection.targets import Target
from evals.nuisance_admission import AdmittedServer
from evals.nuisance_dossier import write_dossier
from tests.unit.support.test_nuisance_committed_admission_given import (
    the_committed_admission,
    the_committed_census,
)

SERVER = figures.a_classification().server_package


def a_written_dossier(tmp_path: Path, backend: str | None = None) -> Path:
    out = tmp_path / "dossier"
    write_dossier(walk_given.a_nuisance_census(census_given.a_census()), SERVER, out, backend)
    return out


def a_twin_with_its_own_fix_check() -> AdmittedServer:
    """An admitted server with a holdout target among its flaws whose fix check is its own, not
    a copy of the holdout calibration."""
    return next(
        server
        for server in the_committed_admission().servers
        if any(
            flaw.flaw in _holdout_identifiers() and flaw.fix_check.source != "holdout_calibration"
            for flaw in server.flaws
        )
    )


def its_holdout_targets(server: AdmittedServer) -> list[Target]:
    flaws = {flaw.flaw for flaw in server.flaws}
    return [target for target in HOLDOUT_TARGETS if target.flaw_id in flaws]


def a_written_twin_dossier(tmp_path: Path, server: AdmittedServer) -> Path:
    out = tmp_path / "twin-dossier"
    write_dossier(the_committed_census(), server.server_package, out)
    return out


def _holdout_identifiers() -> set[str]:
    return {target.flaw_id for target in HOLDOUT_TARGETS}
