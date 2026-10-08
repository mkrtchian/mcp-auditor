"""The only bridge from an audit report to the grammar, part of the grammar fingerprint. It reads
these domain fields and no other: `tool_reports`, `cases`, `chains`, `payload.arguments`,
`response`, `error`, `blocked_reason`, `eval_result.verdict`, `eval_result.category`,
`goal.first_step.arguments` and `steps`."""

from evals.cve_units import JudgeCategory, Step, Unit, Verdict
from mcp_auditor.domain.models import (
    AttackChain,
    AuditReport,
    EvalResult,
    TestCase,
)


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


def _judgment(result: EvalResult | None) -> tuple[Verdict | None, JudgeCategory | None]:
    if result is None:
        return None, None
    return Verdict(result.verdict.value), JudgeCategory(result.category.value)
