import json
from collections import Counter

from mcp_auditor.domain.models import (
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
            result = case.get("eval_result")  # type: ignore[union-attr]
            if result is None:
                continue
            category = AuditCategory(result["category"])  # type: ignore[index]
            mapping = owasp_mapping_for(category)
            if mapping:
                result["owasp"] = {"code": mapping.code, "title": mapping.title}  # type: ignore[index]


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
    total_cases = sum(len(tr.cases) for tr in report.tool_reports)
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


def format_severity_breakdown(counts: Counter[Severity]) -> str:
    sorted_severities = sorted(counts, reverse=True)
    return ", ".join(f"{counts[sev]} {sev.value}" for sev in sorted_severities)


def _severity_breakdown(findings: list[EvalResult]) -> str:
    counts: Counter[Severity] = Counter(f.severity for f in findings)
    return format_severity_breakdown(counts)
