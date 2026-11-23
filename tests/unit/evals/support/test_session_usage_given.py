from mcp_auditor.domain.models import AuditReport, ProviderUsage


def a_report_throttled(times: int) -> AuditReport:
    return AuditReport(
        server_command="test",
        tool_reports=[],
        provider_usage=ProviderUsage(throttled_requests=times),
    )


def a_report_billed(input_tokens: int, output_tokens: int) -> AuditReport:
    usage = ProviderUsage(input_tokens=input_tokens, output_tokens=output_tokens)
    return AuditReport(server_command="test", tool_reports=[], provider_usage=usage)


def a_report_by_phase(total: int, chain: int, judge: int) -> AuditReport:
    return AuditReport(
        server_command="test",
        tool_reports=[],
        provider_usage=ProviderUsage(input_tokens=total),
        chain_usage=ProviderUsage(input_tokens=chain),
        judge_usage=ProviderUsage(input_tokens=judge),
    )
