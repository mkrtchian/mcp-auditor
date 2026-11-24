import asyncio
from collections.abc import Callable

import httpx
from google.genai.errors import ClientError
from langchain_google_genai.chat_models import ChatGoogleGenerativeAIError

from evals.honeypot.runs import run_all
from evals.honeypots import HoneypotAudit, HoneypotConfig
from evals.run_honeypot_suite import counted_audit
from evals.session_usage import SessionThrottles
from mcp_auditor.domain.model_calls import MissedCallCause, MissedModelCall, ModelCallKind
from mcp_auditor.domain.models import AuditReport, ProviderUsage


class FakeHoneypotAudit:
    """Answers every honeypot with an empty report, holding one missed judgment on `missing`."""

    def __init__(self, missing: str, cause: MissedCallCause, throttled_requests: int = 0):
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


def an_audit_raising(error: Exception) -> HoneypotAudit:
    async def audit(honeypot: HoneypotConfig) -> AuditReport:
        raise error

    return audit


def a_suite_running(audit: HoneypotAudit, runs: int) -> Callable[[], int]:
    """Stands for the suite's evaluation: its runs, then a clean exit."""

    def evaluate() -> int:
        asyncio.run(run_all(counted_audit(audit, SessionThrottles()), runs))
        return 0

    return evaluate


def an_error_caused_by_a_forbidden_status() -> ChatGoogleGenerativeAIError:
    # langchain_google_genai raises an unmapped client status as a plain error, its code on the
    # google-genai error it is raised from.
    response = httpx.Response(403, request=httpx.Request("POST", "https://provider.test/v1"))
    body = {"error": {"code": 403, "status": "PERMISSION_DENIED", "message": "key lacks access"}}
    cause = ClientError(403, body, response)
    try:
        raise ChatGoogleGenerativeAIError("Error calling model 'gemini'") from cause
    except ChatGoogleGenerativeAIError as error:
        return error
