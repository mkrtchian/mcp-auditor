import tests.unit.support.grammar_inputs as grammar
from mcp_auditor.domain.models import AuditReport, MissCause, MissedModelCall, ModelCallKind


def a_report_missing(*causes: MissCause) -> AuditReport:
    missed = [
        MissedModelCall(tool_name="read_file", kind=ModelCallKind.JUDGMENT, cause=cause, detail="")
        for cause in causes
    ]
    return grammar.a_report().model_copy(update={"missed_model_calls": missed})
