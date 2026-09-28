from collections.abc import Sequence
from typing import Any

from evals.draw_judge_cases import (
    Strata,
    candidates_from_cve,
    candidates_from_honeypot,
)
from evals.judge_draw_checks import SourceReport
from evals.judge_fixture import CaseLabel, JudgeCase, JudgeFixture
from mcp_auditor.domain.models import AuditCategory, EvalVerdict

INFO_LEAKAGE = AuditCategory.INFO_LEAKAGE
INJECTION = AuditCategory.INJECTION

GROUND_TRUTH = {
    ("get_user", INFO_LEAKAGE): EvalVerdict.FAIL,
    ("get_user", INJECTION): EvalVerdict.PASS,
    ("list_items", INJECTION): EvalVerdict.PASS,
}


def a_honeypot_line(tool: str, category: AuditCategory, **overrides: Any) -> dict[str, Any]:
    return {
        "run_index": 0,
        "type": "single_step",
        "tool_name": tool,
        "tool_description": f"The {tool} tool.",
        "category": category.value,
        "description": "Probe the tool",
        "arguments": {"id": 1},
        "response": "ok",
        "error": None,
        "verdict": "fail",
        "justification": "The response leaks a path.",
        "expected_verdict": "fail",
        "correct": True,
        **overrides,
    }


def a_chain_line(tool: str, category: AuditCategory) -> dict[str, Any]:
    return {
        "run_index": 0,
        "type": "chain",
        "tool_name": tool,
        "tool_description": None,
        "category": category.value,
        "goal": "Chain two calls",
        "steps": [],
        "verdict": "fail",
        "justification": "Leaked.",
        "expected_verdict": "fail",
        "correct": True,
    }


def a_cve_line(cve_id: str, **overrides: Any) -> dict[str, Any]:
    line = a_honeypot_line("git_log", INJECTION, **overrides)
    for honeypot_only in ("expected_verdict", "correct"):
        del line[honeypot_only]
    return {"cve_id": cve_id, **line}


def lines_for(tool: str, category: AuditCategory, count: int) -> list[dict[str, Any]]:
    return [a_honeypot_line(tool, category, arguments={"id": index}) for index in range(count)]


def some_cases(count: int, tool: str = "get_user") -> list[JudgeCase]:
    lines = lines_for(tool, INJECTION, count)
    ground_truth = {(tool, INJECTION): EvalVerdict.PASS}
    return candidates_from_honeypot(lines, ground_truth)[(tool, INJECTION)]


def some_cve_cases(count: int, cve_id: str) -> list[JudgeCase]:
    lines = [a_cve_line(cve_id, arguments={"id": index}) for index in range(count)]
    return candidates_from_cve(lines)[cve_id]


def some_strata() -> Strata:
    return Strata(
        fail_cells={"get_user/info_leakage": some_cases(6, "get_user")},
        pass_cells={
            "get_user/injection": some_cases(3, "get_user_pass"),
            "list_items/injection": some_cases(3, "list_items"),
        },
        cve_targets={"CVE-2025-0001": some_cve_cases(4, "CVE-2025-0001")},
    )


def labeled(fixture: JudgeFixture, labels: Sequence[CaseLabel | None]) -> JudgeFixture:
    cases = [
        case.model_copy(update={"label": label, "clause": "J1" if label else None})
        for case, label in zip(fixture.cases, labels, strict=True)
    ]
    return fixture.model_copy(update={"cases": cases})


def a_source_report(commit: str = "c0ffee", dirty: bool = False) -> SourceReport:
    return SourceReport(
        commit=commit,
        dirty=dirty,
        conditions={
            "runs": 3,
            "budget": 10,
            "tools_filtered": True,
            "provider": "openai",
            "model": "gpt-6-luna",
            "judge_model": "gpt-6-judge",
            "reasoning": "none",
            "judge_reasoning": None,
            "grammar_fingerprint": "abc",
        },
    )
