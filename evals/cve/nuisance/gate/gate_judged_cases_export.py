from pathlib import Path

from evals.cve.nuisance.gate.gate_session_model import GateAudit
from evals.export import case_lines, chain_lines, write_jsonl


def export_nuisance_gate_judged_cases(audits: list[GateAudit], report_path: Path) -> None:
    """Chains included, unlike the detection export: a chain verdict can raise an alarm, and the
    gate's alarms may be analyzed."""
    lines = [
        {"server_package": audit.server_package, "run_index": audit.run_index, **line}
        for audit in audits
        for tool_report in audit.report.tool_reports
        for _, line in case_lines(tool_report) + chain_lines(tool_report)
    ]
    write_jsonl(nuisance_gate_export_path(report_path), lines)


def nuisance_gate_export_path(report_path: Path) -> Path:
    return report_path.with_name("nuisance_gate_judged_cases.jsonl")
