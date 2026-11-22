import importlib.util
from pathlib import Path

from evals.cve.detection.calibration_dossier import write_kit
from tests.unit.support import censuses


def a_written_kit(tmp_path: Path) -> Path:
    out = tmp_path / "kit"
    write_kit(censuses.a_census(), censuses.FLAW_WITH_A_CVE, out)
    return out


def places_loaded_through(module_path: Path) -> dict[str, object]:
    spec = importlib.util.spec_from_file_location("kit_places", module_path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.load_places(module.DETECTION_PLACES)
