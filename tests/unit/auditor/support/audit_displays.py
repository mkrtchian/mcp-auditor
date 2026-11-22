from io import StringIO

from rich.console import Console

from mcp_auditor.console import AuditDisplay


def a_display() -> tuple[AuditDisplay, StringIO]:
    buffer = StringIO()
    console = Console(file=buffer, force_terminal=True)
    return AuditDisplay(console=console), buffer


def a_plain_display() -> tuple[AuditDisplay, StringIO]:
    buffer = StringIO()
    console = Console(file=buffer, force_terminal=False, no_color=True, width=100)
    return AuditDisplay(console=console), buffer


def a_ci_display() -> tuple[AuditDisplay, StringIO]:
    buffer = StringIO()
    console = Console(file=buffer, force_terminal=False, no_color=True)
    return AuditDisplay(console=console, ci_mode=True), buffer
