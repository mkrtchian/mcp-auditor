"""Where the audit's reports are written."""

from dataclasses import dataclass
from pathlib import Path

from mcp_auditor.console import AuditDisplay
from mcp_auditor.domain.models import AuditReport
from mcp_auditor.domain.rendering import render_json, render_markdown


@dataclass(frozen=True)
class ReportPaths:
    json: str | None = None
    markdown: str | None = None


def write_reports(report: AuditReport, paths: ReportPaths, display: AuditDisplay) -> None:
    if paths.json:
        Path(paths.json).write_text(render_json(report))
        display.print_report_path(paths.json)
    if paths.markdown:
        Path(paths.markdown).write_text(render_markdown(report))
        display.print_report_path(paths.markdown)
