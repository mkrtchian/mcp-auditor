from pathlib import Path

from evals.cve.detection.session_model import DetectionAudit
from evals.export import case_lines, write_jsonl


def export_detection_judged_cases(audits: list[DetectionAudit], report_path: Path) -> None:
    """Single-step cases only: a target has no per-case ground truth, and chains are
    judged by another prompt."""
    lines = [
        {"flaw_id": audit.flaw_id, "run_index": audit.run_index, **line}
        for audit in audits
        for tool_report in audit.report.tool_reports
        for _, line in case_lines(tool_report)
    ]
    write_jsonl(detection_export_path(report_path), lines)


def detection_export_path(report_path: Path) -> Path:
    return report_path.with_name("detection_judged_cases.jsonl")
