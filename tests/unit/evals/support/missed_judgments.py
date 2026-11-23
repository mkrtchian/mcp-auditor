from mcp_auditor.domain.model_calls import MissedCallCause, MissedModelCall, ModelCallKind
from mcp_auditor.domain.models import AuditReport


def and_a_refused_judgment(report: AuditReport, tool: str, provider_message: str) -> AuditReport:
    return and_a_missed_judgment(report, tool, MissedCallCause.PROVIDER_REFUSAL, provider_message)


def and_a_missed_judgment(
    report: AuditReport, tool: str, cause: MissedCallCause, detail: str
) -> AuditReport:
    missed = MissedModelCall(
        tool_name=tool, kind=ModelCallKind.JUDGMENT, cause=cause, detail=detail
    )
    return report.model_copy(update={"missed_model_calls": [*report.missed_model_calls, missed]})
