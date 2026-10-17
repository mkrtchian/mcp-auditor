from evals.honeypots import HoneypotConfig
from mcp_auditor.domain.models import AuditReport, AuditStep, MissCause, MissedStep, ProviderUsage


class FakeHoneypotAudit:
    """Answers every honeypot with an empty report, holding one missed judgment on `missing`."""

    def __init__(self, missing: str, cause: MissCause, throttled_requests: int = 0):
        self._missing = missing
        self._cause = cause
        self._throttled_requests = throttled_requests

    async def __call__(self, honeypot: HoneypotConfig) -> AuditReport:
        if honeypot.name != self._missing:
            return AuditReport(
                target=honeypot.name, tool_reports=[], provider_usage=ProviderUsage()
            )
        missed = MissedStep(
            tool_name="get_user", step=AuditStep.JUDGMENT, cause=self._cause, detail="300 s waited"
        )
        usage = ProviderUsage(throttled_requests=self._throttled_requests)
        return AuditReport(
            target=honeypot.name, tool_reports=[], provider_usage=usage, missed_steps=[missed]
        )
