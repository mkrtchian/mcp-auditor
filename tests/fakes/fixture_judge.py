import re
from collections import Counter
from typing import cast

from pydantic import BaseModel

from evals.baseline import Baseline
from evals.gate import Cell, Observation
from evals.honeypots import MERGED_GROUND_TRUTH
from mcp_auditor.domain.models import AuditCategory, EvalVerdict, Judgment, Severity, TokenUsage
from mcp_auditor.domain.ports import ProviderRefusal

# The chain honeypot plants its info_leakage flaws as three-step chains (its docstring and
# the comments on each step): a single-step case covers these cells but cannot reach the flaw.
# Every other cell of that server is covered by single-step cases in every recorded run.
CHAIN_ONLY_FLAWS: list[Cell] = [
    ("project_manager", AuditCategory.INFO_LEAKAGE),
    ("user_directory", AuditCategory.INFO_LEAKAGE),
]

_NO_USAGE = TokenUsage()
# `build_judge_prompt` in graph/prompts.py, `build_chain_judge_prompt` in graph/chain_prompts.py.
_SINGLE_STEP_CELL = re.compile(r'the tool "(?P<tool>[^"]+)" has a \*\*(?P<category>\w+)\*\*')
_CHAIN_TOOL = re.compile(r'against "(?P<tool>[^"]+)"')
_CHAIN_CATEGORY = re.compile(r"Target category: (?P<category>\w+)")
_VERDICTS = {Observation.PASS: EvalVerdict.PASS, Observation.FAIL: EvalVerdict.FAIL}


class FixtureJudge:
    """Answers each cell as the fixture observed it, the n-th judgment of a cell reading the
    n-th run (wrapping), with single-step and chain judgments counted apart.
    """

    def __init__(self, fixture: Baseline) -> None:
        self._runs = fixture.observation_runs()
        self._single_step_judgments: Counter[Cell] = Counter()
        self._chain_judgments: Counter[Cell] = Counter()

    async def generate_structured[T: BaseModel](
        self, prompt: str, output_schema: type[T]
    ) -> tuple[T, TokenUsage]:
        if output_schema is not Judgment:
            raise TypeError(f"the fixture judge answers Judgment only, asked {output_schema}")
        judgment = Judgment(
            verdict=self._verdict_for(prompt),
            justification="fixture observation",
            severity=Severity.LOW,
        )
        return cast(T, judgment), _NO_USAGE

    def _verdict_for(self, prompt: str) -> EvalVerdict:
        single_step_cell = _single_step_cell(prompt)
        if single_step_cell is not None:
            if single_step_cell in CHAIN_ONLY_FLAWS:
                return EvalVerdict.PASS
            return self._observed(single_step_cell, self._single_step_judgments)
        return self._observed(_chain_cell(prompt), self._chain_judgments)

    def _observed(self, cell: Cell, judgments: Counter[Cell]) -> EvalVerdict:
        # The generator asks for every category, so cells outside the ground truth get judged.
        if cell not in MERGED_GROUND_TRUTH:
            return EvalVerdict.PASS
        run = self._runs[judgments[cell] % len(self._runs)]
        observation = run.get(cell, Observation.UNCOVERED)
        judgments[cell] += 1
        if observation == Observation.UNCOVERED:
            raise ProviderRefusal(f"the fixture leaves {cell} uncovered", _NO_USAGE)
        return _VERDICTS[observation]


def _single_step_cell(prompt: str) -> Cell | None:
    match = _SINGLE_STEP_CELL.search(prompt)
    if match is None:
        return None
    return match["tool"], AuditCategory(match["category"])


def _chain_cell(prompt: str) -> Cell:
    tool = _CHAIN_TOOL.search(prompt)
    category = _CHAIN_CATEGORY.search(prompt)
    if tool is None or category is None:
        raise ValueError(f"neither a single-step nor a chain judge prompt:\n{prompt}")
    return tool["tool"], AuditCategory(category["category"])
