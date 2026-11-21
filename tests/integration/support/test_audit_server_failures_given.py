import io
from dataclasses import replace

from mcp_auditor.adapters.server_launch import ServerLaunch
from mcp_auditor.audit import Audit
from mcp_auditor.domain.ports import LLMPort
from tests.fakes import RaisingLLM
from tests.integration.support.unconfined_audit import AuditVariant, an_unconfined_audit

PROVIDER_FAILURE = "the model provider went away"


def an_audit_of(launch: ServerLaunch, output: io.StringIO, llm: LLMPort | None = None) -> Audit:
    variant = AuditVariant(output=output)
    return an_unconfined_audit(launch, variant if llm is None else replace(variant, llm=llm))


def a_failing_model(error: Exception | None = None) -> RaisingLLM:
    return RaisingLLM(error or RuntimeError(PROVIDER_FAILURE))
