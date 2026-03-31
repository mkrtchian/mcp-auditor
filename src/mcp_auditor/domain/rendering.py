import json
from collections import Counter
from dataclasses import dataclass, field

from mcp_auditor.domain.models import (
    AttackChain,
    AuditCategory,
    AuditReport,
    EvalResult,
    EvalVerdict,
    Severity,
    ToolReport,
)
from mcp_auditor.domain.owasp import owasp_label_for, owasp_mapping_for


def render_summary(report: AuditReport) -> str:
    tool_count = len(report.tool_reports)
    findings = report.findings
    finding_count = len(findings)
    if finding_count == 0:
        return f"{report.target}: {tool_count} tools, no findings"
    severity_breakdown = _severity_breakdown(findings)
    return f"{report.target}: {tool_count} tools, {finding_count} findings ({severity_breakdown})"


def render_json(report: AuditReport) -> str:
    data = report.model_dump(mode="json")
    _inject_owasp_into_json(data)
    return json.dumps(data, indent=2)


def _inject_owasp_into_json(data: dict[str, object]) -> None:
    for tool_report in data.get("tool_reports", []):  # type: ignore[union-attr]
        for case in tool_report.get("cases", []):  # type: ignore[union-attr]
            _inject_owasp_on_result(case.get("eval_result"))  # type: ignore[union-attr]
        for chain in tool_report.get("chains", []):  # type: ignore[union-attr]
            _inject_owasp_on_result(chain.get("eval_result"))  # type: ignore[union-attr]


def _inject_owasp_on_result(result: dict[str, object] | None) -> None:
    if result is None:
        return
    category = AuditCategory(result["category"])  # type: ignore[arg-type]
    mapping = owasp_mapping_for(category)
    if mapping:
        result["owasp"] = {"code": mapping.code, "title": mapping.title}


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
    owasp = owasp_label_for(result.category)
    category_display = f"{result.category} / {owasp}" if owasp else str(result.category)
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
    lines = [f"### CHAIN: {chain.goal.description}"]
    lines.append(f"**Category**: {chain.goal.category}")
    lines.append("**Steps**:")
    for i, step in enumerate(chain.steps, 1):
        response_snippet = _truncate_chain_response(step.response or step.error or "")
        obs_text = f" -- {step.observation}" if step.observation else ""
        lines.append(f"  {i}. `{step.payload.arguments}` -> {response_snippet}{obs_text}")
    if chain.eval_result:
        if chain.eval_result.verdict == EvalVerdict.FAIL:
            lines.append(f"**Verdict**: FAIL ({chain.eval_result.severity})")
        else:
            lines.append("**Verdict**: PASS")
        lines.append(f"**Justification**: {chain.eval_result.justification}")
    return "\n".join(lines)


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
    judged_cases = [c for c in tool_report.cases if c.eval_result is not None]
    judged_chains = [ch for ch in tool_report.chains if ch.eval_result is not None]
    all_results = [c.eval_result for c in judged_cases if c.eval_result] + [
        ch.eval_result for ch in judged_chains if ch.eval_result
    ]
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
