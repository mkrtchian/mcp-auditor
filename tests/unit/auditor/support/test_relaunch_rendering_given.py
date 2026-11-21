from mcp_auditor.domain.models import AuditReport
from mcp_auditor.domain.server_liveness import Relaunch, RelaunchCause
from tests.unit.auditor.support import report_builders as reports

LOST_ARGUMENTS = {"user_id": "1; sleep 999"}
STUCK_ARGUMENTS = {"user_id": "a" * 10}


def a_report_with_two_relaunches_on_get_user(last_succeeded: bool = True) -> AuditReport:
    report = reports.a_two_tool_report()
    report.relaunches = [
        Relaunch(
            tool_name="get_user",
            arguments=LOST_ARGUMENTS,
            cause=RelaunchCause.LOST_CONNECTION,
            succeeded=True,
        ),
        Relaunch(
            tool_name="get_user",
            arguments=STUCK_ARGUMENTS,
            cause=RelaunchCause.UNANSWERED_PING,
            succeeded=last_succeeded,
        ),
    ]
    return report


def a_report_with_a_chain_cut_by_a_relaunch() -> AuditReport:
    chain = reports.a_chain(judge_result=reports.a_chain_fail_result())
    chain.cut_by_relaunch = True
    report = reports.a_report_with_chain_finding()
    report.tool_reports[0].chains = [chain]
    return report
