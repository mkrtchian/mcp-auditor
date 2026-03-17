import json

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from mcp_auditor.domain.models import AuditPayload, AuditReport, TokenUsage


class AuditDisplay:
    def __init__(self, console: Console | None = None):
        self._console = console or Console()

    def print_header(self, target_command: str) -> None:
        self._console.print(Panel(target_command, title="MCP Auditor"))

    def print_discovery(self, tool_count: int, tool_names: list[str]) -> None:
        names = ", ".join(tool_names)
        self._console.print(f"Discovered {tool_count} tools: {names}")

    def print_tool_start(
        self,
        tool_index: int,
        tool_count: int,
        tool_name: str,
        case_count: int,
    ) -> None:
        self._console.print(f"[{tool_index}/{tool_count}] {tool_name} ({case_count} test cases)")

    def print_verdict(
        self,
        case_index: int,
        case_count: int,
        category: str,
        description: str,
        verdict: str,
        severity: str,
    ) -> None:
        label = Text()
        if verdict.lower() == "pass":
            label.append("PASS", style="green")
        else:
            label.append("FAIL", style="red")
            label.append(f" [{severity}]")
        label.append(f" ({case_index}/{case_count}) {category}: {description}")
        self._console.print(label)

    def print_tool_done(self, tool_name: str, pass_count: int, fail_count: int) -> None:
        self._console.print(f"{tool_name}: {pass_count} passed, {fail_count} failed")

    def print_summary_table(self, report: AuditReport) -> None:
        table = Table(title="Audit Summary")
        table.add_column("Tool")
        table.add_column("Tests", justify="right")
        table.add_column("Pass", justify="right", style="green")
        table.add_column("Fail", justify="right", style="red")
        for tool_report in report.tool_reports:
            total = len(tool_report.results)
            passes = sum(1 for r in tool_report.results if r.verdict.value == "pass")
            fails = total - passes
            table.add_row(tool_report.tool.name, str(total), str(passes), str(fails))
        self._console.print(table)

    def print_cost(self, usage: TokenUsage) -> None:
        self._console.print(f"Tokens: {usage.input_tokens:,} input, {usage.output_tokens:,} output")

    def print_dry_run_payloads(self, tool_name: str, cases: list[AuditPayload]) -> None:
        table = Table(title=f"Dry Run: {tool_name}")
        table.add_column("Category")
        table.add_column("Description")
        table.add_column("Arguments")
        for case in cases:
            table.add_row(case.category.value, case.description, json.dumps(case.arguments))
        self._console.print(table)

    def print_report_path(self, path: str) -> None:
        self._console.print(f"Report written to: {path}")
