"""What the grammar grades: a case or a whole chain, as the report records it, or a sequence
of calibration exchanges. A chain blocked at its first step keeps no step in the report and is
read on its planned first step."""

from collections.abc import Sequence
from typing import Any, NamedTuple

from mcp_auditor.domain.models import (
    AttackChain,
    AuditCategory,
    AuditReport,
    EvalResult,
    EvalVerdict,
    TestCase,
)


class Step(NamedTuple):
    arguments: dict[str, Any]
    outputs: tuple[str, ...]


class Unit(NamedTuple):
    steps: tuple[Step, ...]
    verdict: EvalVerdict | None  # None: not judged (blocked, refused, or a calibration call)
    category: AuditCategory | None
    blocked: bool  # independent of verdict: a chain blocked after step 1 is still judged


def units_of(report: AuditReport) -> list[Unit]:
    return [
        unit
        for tool_report in report.tool_reports
        for unit in (
            *(_case_unit(case) for case in tool_report.cases),
            *(_chain_unit(chain) for chain in tool_report.chains),
        )
    ]


def _case_unit(case: TestCase) -> Unit:
    response = case.response if not isinstance(case.response, dict) else str(case.response)
    step = Step(case.payload.arguments, _present(response, case.error))
    return Unit((step,), *_judgment(case.eval_result), blocked=case.blocked_reason is not None)


def _chain_unit(chain: AttackChain) -> Unit:
    if chain.steps:
        steps = tuple(
            Step(step.payload.arguments, _present(step.response, step.error))
            for step in chain.steps
        )
    else:
        steps = (Step(chain.goal.first_step.arguments, ()),)
    return Unit(steps, *_judgment(chain.eval_result), blocked=chain.blocked_reason is not None)


def _present(*texts: str | None) -> tuple[str, ...]:
    return tuple(text for text in texts if text is not None)


def _judgment(result: EvalResult | None) -> tuple[EvalVerdict | None, AuditCategory | None]:
    if result is None:
        return None, None
    return result.verdict, result.category


def unit_of_exchanges(exchanges: Sequence[tuple[dict[str, Any], str]]) -> Unit:
    steps = tuple(Step(arguments, (output,)) for arguments, output in exchanges)
    return Unit(steps, verdict=None, category=None, blocked=False)
