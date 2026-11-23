from evals.gate import Observation
from evals.ground_truth import Cell
from mcp_auditor.domain.models import (
    AttackChain,
    AuditCategory,
    AuditPayload,
    ChainGoal,
    EvalVerdict,
    Judgment,
    TestCase,
    ToolDefinition,
)
from mcp_auditor.domain.ports import LLMPort
from mcp_auditor.graph.chain_prompts import build_chain_judge_prompt
from mcp_auditor.graph.prompts import build_attack_generation_prompt, build_judge_prompt
from tests.fakes.fixture_judge import CHAIN_ONLY_FLAWS, FixtureJudge
from tests.unit.evals.support.honeypot_baselines import ObservationRuns, a_baseline

A_CELL_FAILED_IN_THE_FIRST_RUN_ONLY: Cell = ("search_products", AuditCategory.INJECTION)
A_CHAIN_ONLY_CELL_FAILED_IN_THE_SECOND_RUN_ONLY: Cell = CHAIN_ONLY_FLAWS[0]
A_CELL_OUTSIDE_THE_GROUND_TRUTH: Cell = ("get_user", AuditCategory.INPUT_VALIDATION)

THREE_RUNS: ObservationRuns = [
    {
        A_CELL_FAILED_IN_THE_FIRST_RUN_ONLY: Observation.FAIL,
        A_CHAIN_ONLY_CELL_FAILED_IN_THE_SECOND_RUN_ONLY: Observation.PASS,
    },
    {
        A_CELL_FAILED_IN_THE_FIRST_RUN_ONLY: Observation.PASS,
        A_CHAIN_ONLY_CELL_FAILED_IN_THE_SECOND_RUN_ONLY: Observation.FAIL,
    },
    {
        A_CELL_FAILED_IN_THE_FIRST_RUN_ONLY: Observation.PASS,
        A_CHAIN_ONLY_CELL_FAILED_IN_THE_SECOND_RUN_ONLY: Observation.PASS,
    },
]


def a_fixture_judge(runs: ObservationRuns = THREE_RUNS) -> FixtureJudge:
    return FixtureJudge(a_baseline(runs=runs))


def the_runs_with_uncovered(cell: Cell) -> ObservationRuns:
    return [{**run, cell: Observation.UNCOVERED} for run in THREE_RUNS]


def the_runs_without(cell: Cell) -> ObservationRuns:
    return [{other: seen for other, seen in run.items() if other != cell} for run in THREE_RUNS]


def an_attack_prompt(categories: list[AuditCategory]) -> str:
    return build_attack_generation_prompt(_a_tool("get_user"), 5, categories)


def a_single_step_judge_prompt(cell: Cell) -> str:
    tool, category = cell
    case = TestCase(payload=_a_payload(category), response="an answer")
    return build_judge_prompt(_a_tool(tool), case)


def a_chain_judge_prompt(cell: Cell) -> str:
    tool, category = cell
    goal = ChainGoal(description="a goal", category=category, first_step=_a_payload(category))
    return build_chain_judge_prompt(_a_tool(tool), AttackChain(goal=goal, steps=[]))


async def verdicts_of(judge: LLMPort, prompt: str, calls: int) -> list[EvalVerdict]:
    return [(await judge.generate_structured(prompt, Judgment))[0].verdict for _ in range(calls)]


def _a_tool(name: str) -> ToolDefinition:
    return ToolDefinition(
        name=name, description="A tool under audit.", input_schema={"type": "object"}
    )


def _a_payload(category: AuditCategory) -> AuditPayload:
    return AuditPayload(category=category, description="a case", arguments={})
