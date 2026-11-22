from pathlib import Path

from evals.cve.census.work import AgentRole
from tests.unit.support import census_draws

A_DRAWN_FLAW = census_draws.A_DRAWN_FLAW
REQUESTED = "claude-opus-5-5"
ANSWERED = "claude-opus-4-8"


def a_written_census_whose_drawn_flaw_calibrator_fell_back(tmp_path: Path) -> Path:
    with_draw = census_draws.a_census_with_draw(census_draws.a_draw())
    agents = [
        agent.model_copy(update={"model": REQUESTED, "fallback_model": ANSWERED})
        if agent.scope == A_DRAWN_FLAW and agent.role == AgentRole.CALIBRATOR
        else agent
        for agent in with_draw.agents
    ]
    path = tmp_path / "census.json"
    path.write_text(with_draw.model_copy(update={"agents": agents}).model_dump_json(indent=2))
    return path
