from evals.metrics import VerdictMap, aggregate_verdicts
from mcp_auditor.domain.models import AuditReport, ProviderUsage


def merged(verdicts: VerdictMap, report: AuditReport, reports: list[AuditReport]) -> None:
    assert verdicts == {
        cell: verdict for each in reports for cell, verdict in aggregate_verdicts(each).items()
    }
    assert report.tool_reports == [tool for each in reports for tool in each.tool_reports]
    assert report.provider_usage == ProviderUsage(input_tokens=600, output_tokens=60)
    assert report.missed_model_calls == [
        step for each in reports for step in each.missed_model_calls
    ]
