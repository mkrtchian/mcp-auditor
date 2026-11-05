from pathlib import Path

import tests.unit.support.test_census_figures_given as figures
import tests.unit.support.test_holdout_census_given as census_given
import tests.unit.support.test_nuisance_walk_given as walk_given
from evals.nuisance_dossier import write_dossier

SERVER = figures.a_classification().server_package


def a_written_dossier(tmp_path: Path, backend: str | None = None) -> Path:
    out = tmp_path / "dossier"
    write_dossier(walk_given.a_nuisance_census(census_given.a_census()), SERVER, out, backend)
    return out
