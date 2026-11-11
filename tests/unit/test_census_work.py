from pathlib import Path

import pytest
from pydantic import ValidationError

import tests.unit.support.test_census_work_given as given
from evals.cve.census.census import load_census
from evals.cve.census.work import AgentRecord, AgentRole, read_jsonl
from tests.unit.support.test_detection_draw_record_given import A_DRAWN_FLAW


def test_an_agent_that_continued_on_the_fallback_model_is_one_record_satisfying_the_draw(
    tmp_path: Path,
):
    census = load_census(given.a_written_census_whose_drawn_flaw_agents_fell_back(tmp_path))

    calibrators = [
        agent
        for agent in census.agents
        if agent.scope == A_DRAWN_FLAW and agent.role == AgentRole.CALIBRATOR
    ]
    assert [(agent.model, agent.fallback_model) for agent in calibrators] == [
        (given.REQUESTED, given.ANSWERED)
    ]


def test_a_fallback_model_equal_to_the_requested_model_is_refused():
    with pytest.raises(ValidationError, match="fallback_model"):
        AgentRecord(
            role=AgentRole.CALIBRATOR,
            scope=A_DRAWN_FLAW,
            model=given.REQUESTED,
            fallback_model=given.REQUESTED,
        )


def test_two_records_of_one_role_and_scope_with_no_fallback_read_as_two_agents(tmp_path: Path):
    agents = read_jsonl(given.a_jsonl_of_two_calibrators_of_one_flaw(tmp_path), AgentRecord)

    assert len(agents) == 2
    assert all(agent.fallback_model is None for agent in agents)
