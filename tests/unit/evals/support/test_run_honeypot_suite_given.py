from evals.honeypots import HoneypotConfig
from mcp_auditor.domain.models import (
    AuditReport,
    MissCause,
    MissedModelCall,
    ModelCallKind,
    ProviderUsage,
)


class FakeHoneypotAudit:
    """Answers every honeypot with an empty report, holding one missed judgment on `missing`."""

    def __init__(self, missing: str, cause: MissCause, throttled_requests: int = 0):
        self._missing = missing
        self._cause = cause
        self._throttled_requests = throttled_requests

    async def __call__(self, honeypot: HoneypotConfig) -> AuditReport:
        if honeypot.name != self._missing:
            return AuditReport(
                server_command=honeypot.name, tool_reports=[], provider_usage=ProviderUsage()
            )
        missed = MissedModelCall(
            tool_name="get_user",
            kind=ModelCallKind.JUDGMENT,
            cause=self._cause,
            detail="300 s waited",
        )
        usage = ProviderUsage(throttled_requests=self._throttled_requests)
        return AuditReport(
            server_command=honeypot.name,
            tool_reports=[],
            provider_usage=usage,
            missed_model_calls=[missed],
        )
