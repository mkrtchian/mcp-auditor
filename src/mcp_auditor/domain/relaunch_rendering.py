"""How the reports word the relaunches and the calls not sent (ADR 036)."""

from mcp_auditor.domain.models import AuditReport, CoverageGap
from mcp_auditor.domain.server_liveness import Relaunch, RelaunchCause, UnsentCause
from mcp_auditor.domain.server_watch import RELAUNCHES_IN_A_ROW, TIMEOUTS_IN_A_ROW

RELAUNCH_CAUSE_LABELS = {
    RelaunchCause.LOST_CONNECTION: "the connection to the server was lost",
    RelaunchCause.UNANSWERED_PING: "the call timed out and the server did not answer the ping",
    RelaunchCause.STUCK: (
        "the calls of two tools in a row kept timing out, the server was taken as stuck"
    ),
}

UNSENT_CAUSE_LABELS = {
    UnsentCause.TOOL_TIMING_OUT: f"the tool timed out {TIMEOUTS_IN_A_ROW} times in a row",
    UnsentCause.RELAUNCHES_IN_A_ROW: (
        f"the tool's calls led to {RELAUNCHES_IN_A_ROW} relaunches in a row"
    ),
    UnsentCause.SERVER_DOWN: "the server was taken as down",
}

CUT_BY_RELAUNCH_LINE = (
    "**Cut by a relaunch**: the server was relaunched after the last step, "
    "the chain is judged on the steps made"
)


def describe_relaunch(relaunch: Relaunch) -> str:
    cause = RELAUNCH_CAUSE_LABELS[relaunch.cause]
    if relaunch.succeeded:
        return f"{cause}, the server was relaunched"
    return f"{cause}, the relaunch failed and the server was taken as down"


def describe_unsent_calls(gap: CoverageGap) -> str:
    counts = [_counted(gap.unsent_cases, "case"), _counted(gap.unsent_chains, "chain")]
    not_sent = [count for count in counts if count]
    description = f", {' and '.join(not_sent)} not sent" if not_sent else ""
    if gap.unsent_cause is not None:
        description += f" ({UNSENT_CAUSE_LABELS[gap.unsent_cause]})"
    return description


def _counted(count: int, noun: str) -> str:
    if count == 0:
        return ""
    return f"{count} {noun}" if count == 1 else f"{count} {noun}s"


def render_relaunch_summary_lines(report: AuditReport) -> list[str]:
    if not report.relaunches:
        return []
    line = f"**Relaunches**: {len(report.relaunches)}"
    # A resumed audit starts on a server just launched, so a failed relaunch can come
    # before others.
    failed = sum(1 for relaunch in report.relaunches if not relaunch.succeeded)
    if failed:
        line += f", {failed} failed and the server was taken as down"
    return [line]


def render_relaunch_lines(relaunches: list[Relaunch]) -> list[str]:
    return [
        f"**Relaunch**: after `{relaunch.arguments}`, {describe_relaunch(relaunch)}\n"
        for relaunch in relaunches
    ]
