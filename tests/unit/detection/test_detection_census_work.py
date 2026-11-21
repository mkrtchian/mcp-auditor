from pathlib import Path

import pytest
from pydantic import ValidationError

import tests.unit.detection.support.test_detection_census_work_given as given
from evals.cve.census.census import load_census
from evals.cve.census.work import AgentRecord, AgentRole


def test_a_census_whose_drawn_flaw_only_calibrator_carries_a_fallback_model_loads(
    tmp_path: Path,
):
    load_census(given.a_written_census_whose_drawn_flaw_calibrator_fell_back(tmp_path))


def test_a_fallback_model_equal_to_the_requested_model_is_refused():
    with pytest.raises(ValidationError, match="fallback_model"):
        AgentRecord(
            role=AgentRole.CALIBRATOR,
            scope=given.A_DRAWN_FLAW,
            model=given.REQUESTED,
            fallback_model=given.REQUESTED,
        )
