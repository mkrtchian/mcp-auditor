import importlib.util
from pathlib import Path

import tests.unit.support.test_census_given as census_given
from evals.calibration_dossier import write_kit


def a_written_kit(tmp_path: Path) -> Path:
    out = tmp_path / "kit"
    write_kit(census_given.a_census(), census_given.FLAW_WITH_A_CVE, out)
    return out


def places_loaded_through(module_path: Path) -> dict[str, object]:
    spec = importlib.util.spec_from_file_location("kit_cve_places", module_path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.load_places(module.HOLDOUT_PLACES)
