from evals.baseline import Baseline, load_baseline
from evals.fault_harness import FIXTURE_PATH
from evals.gate import Cell, Observation, cell_key
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

# Observed FAIL, PASS, PASS in the fixture's three runs.
A_CELL_FAILED_IN_THE_FIRST_RUN_ONLY: Cell = ("execute_query", AuditCategory.INJECTION)
# Observed PASS, FAIL, PASS: a chain-only cell.
A_CHAIN_ONLY_CELL_FAILED_IN_THE_SECOND_RUN_ONLY: Cell = (
    "project_manager",
    AuditCategory.INFO_LEAKAGE,
)
A_CELL_OUTSIDE_THE_GROUND_TRUTH: Cell = ("get_user", AuditCategory.INPUT_VALIDATION)


def the_fixture() -> Baseline:
    fixture = load_baseline(FIXTURE_PATH)
    assert fixture is not None
    return fixture


def the_fixture_with_uncovered(cell: Cell) -> Baseline:
    fixture = the_fixture()
    runs = [{**run, cell_key(cell): Observation.UNCOVERED} for run in fixture.runs]
    return fixture.model_copy(update={"runs": runs})


def the_fixture_without(cell: Cell) -> Baseline:
    fixture = the_fixture()
    runs = [
        {key: seen for key, seen in run.items() if key != cell_key(cell)} for run in fixture.runs
    ]
    return fixture.model_copy(update={"runs": runs})


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
