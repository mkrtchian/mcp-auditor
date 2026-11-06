"""The isolated calibration kit `write_kit` assembles for one holdout candidate."""

import json
import subprocess
import sys
from pathlib import Path

import tests.unit.support.test_calibration_dossier_given as given
from evals.census_classification import Classification
from evals.census_draw import CalibrationCard


def test_the_fixture_format_embeds_the_card_and_classification_schemas(tmp_path: Path):
    out = given.a_written_kit(tmp_path)

    fixture_format = (out / "fixture_format.md").read_text()
    assert json.dumps(CalibrationCard.model_json_schema(), indent=2) in fixture_format
    assert json.dumps(Classification.model_json_schema(), indent=2) in fixture_format


def test_the_places_file_loads_through_the_copied_loader(tmp_path: Path):
    out = given.a_written_kit(tmp_path)

    places = given.places_loaded_through(out / "evals" / "cve_places.py")

    assert places


def test_a_stand_in_loads_through_the_copied_loader(tmp_path: Path):
    out = given.a_written_kit(tmp_path)
    script = (
        "from evals import public_stand_ins\n"
        "print(public_stand_ins.STAND_INS_DIRECTORY)\n"
        "print(public_stand_ins.stand_in('example.com').host)\n"
    )

    result = subprocess.run(
        [sys.executable, "-c", script], cwd=out, capture_output=True, text=True, check=True
    )

    directory, host = result.stdout.split()
    assert Path(directory).resolve() == (out / "evals" / "stand_ins").resolve()
    assert host == "example.com"
