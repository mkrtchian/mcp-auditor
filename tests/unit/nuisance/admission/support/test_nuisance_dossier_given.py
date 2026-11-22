from pathlib import Path

import tests.unit.support.nuisance_walks as walks
from evals.cve.nuisance.admission.admission import AdmittedServer
from evals.cve.nuisance.admission.dossier import write_dossier
from tests.unit.support import censuses
from tests.unit.support.committed_nuisance_admission import the_committed_walk_inputs

SERVER = censuses.a_classification().server_package


def a_written_dossier(tmp_path: Path, backend: str | None = None) -> Path:
    out = tmp_path / "dossier"
    write_dossier(walks.walk_inputs_of(censuses.a_census()), SERVER, out, backend)
    return out


def a_written_dossier_of(tmp_path: Path, server: AdmittedServer) -> Path:
    out = tmp_path / "holdout-target-dossier"
    write_dossier(the_committed_walk_inputs(), server.server_package, out)
    return out
