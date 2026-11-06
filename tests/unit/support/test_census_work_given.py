from pathlib import Path

import tests.unit.support.test_census_draw_given as draw_given
import tests.unit.support.test_holdout_census_given as census_given
from evals.census_work import AgentRecord, AgentRole
from tests.unit.support.test_census_draw_given import A_DRAWN_FLAW

REQUESTED = "claude-opus-5-5"
ANSWERED = "claude-opus-4-8"


def a_written_census_whose_drawn_flaw_agents_fell_back(tmp_path: Path) -> Path:
    with_draw = draw_given.a_census_with_draw(draw_given.a_draw())
    agents = [
        agent.model_copy(update={"model": REQUESTED, "fallback_model": ANSWERED})
        if agent.scope == A_DRAWN_FLAW
        else agent
        for agent in with_draw.agents
    ]
    return census_given.written(tmp_path, with_draw.model_copy(update={"agents": agents}))


def a_jsonl_of_two_calibrators_of_one_flaw(tmp_path: Path) -> Path:
    record = AgentRecord(role=AgentRole.CALIBRATOR, scope=A_DRAWN_FLAW, model=REQUESTED)
    path = tmp_path / "agents.jsonl"
    path.write_text(f"{record.model_dump_json()}\n{record.model_dump_json()}\n")
    return path
