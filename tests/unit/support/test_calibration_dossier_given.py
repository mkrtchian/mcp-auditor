import importlib.util
from pathlib import Path

import tests.unit.support.test_census_draw_given as draw_given
import tests.unit.support.test_holdout_census_given as census_given
from evals.calibration_dossier import write_kit
from evals.census_draw import CalibrationCard, DrawRecord


def a_written_kit(tmp_path: Path) -> Path:
    out = tmp_path / "kit"
    write_kit(census_given.a_census(), census_given.FLAW_WITH_A_CVE, out)
    return out


def a_ready_draw_whose_card_leaves_every_optional_field_unset() -> DrawRecord:
    unset = {
        name: None
        for name, field in CalibrationCard.model_fields.items()
        if not field.is_required()
    }
    card = draw_given.a_card(draw_given.A_DRAWN_FLAW).model_copy(update=unset)
    return draw_given.a_ready_draw().model_copy(update={"cards": [card]})


def places_loaded_through(module_path: Path) -> dict[str, object]:
    spec = importlib.util.spec_from_file_location("kit_cve_places", module_path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.load_places(module.HOLDOUT_PLACES)
