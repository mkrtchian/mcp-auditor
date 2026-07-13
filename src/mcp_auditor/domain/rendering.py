import json
from collections import Counter
from dataclasses import dataclass, field

from mcp_auditor.domain.models import (
    AttackChain,
    AuditReport,
    ChainStep,
    EvalResult,
    EvalVerdict,
    Severity,
    ToolReport,
)
from mcp_auditor.domain.owasp import category_with_owasp_label


def render_summary(report: AuditReport) -> str:
    tool_count = len(report.tool_reports)
    findings = report.findings
    finding_count = len(findings)
    if finding_count == 0:
        return f"{report.target}: {tool_count} tools, no findings"
    severity_breakdown = _severity_breakdown(findings)
    return f"{report.target}: {tool_count} tools, {finding_count} findings ({severity_breakdown})"


def render_json(report: AuditReport) -> str:
    return json.dumps(report.model_dump(mode="json"), indent=2)


def render_markdown(report: AuditReport) -> str:
    sections = [
        "# MCP Audit Report\n",
        _render_summary_section(report),
    ]
    for tool_report in report.tool_reports:
        sections.append(_render_tool_section(tool_report))
    return "\n".join(sections)


def _render_summary_section(report: AuditReport) -> str:
    tool_count = len(report.tool_reports)
    total_cases = sum(len(tr.cases) + len(tr.chains) for tr in report.tool_reports)
    findings = report.findings
    finding_count = len(findings)
    lines = [
        "## Summary\n",
        f"**Target**: {report.target}",
        f"**Tools audited**: {tool_count}",
        f"**Test cases**: {total_cases}",
        f"**Findings**: {finding_count}",
    ]
    if finding_count > 0:
        lines.append(f"  {_severity_breakdown(findings)}")
    usage = report.token_usage
    lines.append(f"**Token usage**: {usage.input_tokens} input, {usage.output_tokens} output")
    return "\n".join(lines)


def _render_tool_section(tool_report: ToolReport) -> str:
    lines = [f"\n## {tool_report.tool.name}\n"]
    for case in tool_report.cases:
        if case.eval_result is None:
            continue
        lines.append(_render_result_section(case.eval_result))
    for chain in tool_report.chains:
        lines.append(_render_chain_section(chain))
    return "\n".join(lines)


def _render_result_section(result: EvalResult) -> str:
    category_display = category_with_owasp_label(result.category)
    if result.verdict == EvalVerdict.PASS:
        heading = f"### PASS -- {category_display} (-)"
    else:
        heading = f"### FAIL -- {category_display} ({result.severity})"
    lines = [
        heading,
        f"**Payload**: `{result.payload}`",
        f"**Justification**: {result.justification}",
    ]
    return "\n".join(lines)


def _render_chain_section(chain: AttackChain) -> str:
    lines = [
        f"### CHAIN: {chain.goal.description}",
        f"**Category**: {chain.goal.category}",
        _render_chain_steps(chain.steps),
    ]
    if chain.eval_result:
        lines.append(_render_chain_verdict(chain.eval_result))
    return "\n".join(lines)


def _render_chain_steps(steps: list[ChainStep]) -> str:
    lines = ["**Steps**:"]
    for i, step in enumerate(steps, 1):
        response_snippet = _truncate_chain_response(step.response or step.error or "")
        observation_text = f" -- {step.observation}" if step.observation else ""
        lines.append(f"  {i}. `{step.payload.arguments}` -> {response_snippet}{observation_text}")
    return "\n".join(lines)


def _render_chain_verdict(result: EvalResult) -> str:
    if result.verdict == EvalVerdict.FAIL:
        verdict_line = f"**Verdict**: FAIL ({result.severity})"
    else:
        verdict_line = "**Verdict**: PASS"
    return f"{verdict_line}\n**Justification**: {result.justification}"


def _truncate_chain_response(text: str, max_length: int = 80) -> str:
    if len(text) <= max_length:
        return text
    return text[: max_length - 1] + "..."


def format_severity_breakdown(counts: Counter[Severity]) -> str:
    sorted_severities = sorted(counts, reverse=True)
    return ", ".join(f"{counts[sev]} {sev.value}" for sev in sorted_severities)


def _severity_breakdown(findings: list[EvalResult]) -> str:
    counts: Counter[Severity] = Counter(f.severity for f in findings)
    return format_severity_breakdown(counts)


@dataclass
class ToolSummary:
    name: str
    judged: int = 0
    passed: int = 0
    failed: int = 0
    severity_counts: Counter[Severity] = field(default_factory=lambda: Counter[Severity]())


def summarize_tools(report: AuditReport) -> list[ToolSummary]:
    return [_summarize_tool_report(tr) for tr in report.tool_reports]


def _summarize_tool_report(tool_report: ToolReport) -> ToolSummary:
    all_results = tool_report.eval_results
    passed = sum(1 for r in all_results if r.verdict == EvalVerdict.PASS)
    severity_counts: Counter[Severity] = Counter(
        r.severity for r in all_results if r.verdict == EvalVerdict.FAIL
    )
    return ToolSummary(
        name=tool_report.tool.name,
        judged=len(all_results),
        passed=passed,
        failed=len(all_results) - passed,
        severity_counts=severity_counts,
    )
