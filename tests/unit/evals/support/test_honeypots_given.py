import asyncio
from dataclasses import dataclass, field

from evals.honeypots import HONEYPOTS, HoneypotConfig
from mcp_auditor.domain.model_calls import MissedCallCause, MissedModelCall, ModelCallKind
from mcp_auditor.domain.models import (
    AuditCategory,
    AuditPayload,
    AuditReport,
    EvalVerdict,
    JudgeResult,
    ProviderUsage,
    Severity,
    TestCase,
    ToolDefinition,
    ToolReport,
)


@dataclass(frozen=True)
class HoneypotReports:
    """One fixed report per honeypot, as the audit of each would return it."""

    by_honeypot: dict[str, AuditReport]

    async def audit(self, honeypot: HoneypotConfig) -> AuditReport:
        return self.by_honeypot[honeypot.name]


@dataclass(frozen=True)
class ReverseFinishingReports:
    """Each honeypot's audit ends only once the next honeypot's has, the last one first."""

    reports: HoneypotReports
    finished: dict[str, asyncio.Event] = field(
        default_factory=lambda: {honeypot.name: asyncio.Event() for honeypot in HONEYPOTS}
    )

    async def audit(self, honeypot: HoneypotConfig) -> AuditReport:
        position = HONEYPOTS.index(honeypot)
        if position + 1 < len(HONEYPOTS):
            async with asyncio.timeout(_NEVER_IN_SEQUENCE):
                await self.finished[HONEYPOTS[position + 1].name].wait()
        self.finished[honeypot.name].set()
        return await self.reports.audit(honeypot)


_NEVER_IN_SEQUENCE = 1.0  # seconds: awaited one after the other, these audits would wait forever


class SubtleHoneypotCrashed(Exception):
    pass


@dataclass(frozen=True)
class OneFailingHoneypot:
    """The subtle honeypot's audit fails at once, the others wait until they are cancelled."""

    cancelled: list[str] = field(default_factory=list[str])

    async def audit(self, honeypot: HoneypotConfig) -> AuditReport:
        if honeypot.name == "subtle":
            raise SubtleHoneypotCrashed
        try:
            await asyncio.Event().wait()
        except asyncio.CancelledError:
            self.cancelled.append(honeypot.name)
            raise
        raise AssertionError("unreachable: the event is never set")


def a_report_per_honeypot_finishing_in_reverse() -> ReverseFinishingReports:
    return ReverseFinishingReports(a_report_per_honeypot())


def a_report_per_honeypot() -> HoneypotReports:
    return HoneypotReports(
        {
            "honeypot": _a_report(
                "get_user", EvalVerdict.FAIL, ProviderUsage(input_tokens=100, output_tokens=10)
            ).model_copy(update={"missed_model_calls": [_a_refused_judgment("get_user")]}),
            "subtle": _a_report(
                "list_items", EvalVerdict.PASS, ProviderUsage(input_tokens=200, output_tokens=20)
            ),
            "chain_honeypot": _a_report(
                "project_manager",
                EvalVerdict.FAIL,
                ProviderUsage(input_tokens=300, output_tokens=30),
            ),
        }
    )


def _a_report(tool: str, verdict: EvalVerdict, usage: ProviderUsage) -> AuditReport:
    result = JudgeResult(
        tool_name=tool,
        category=AuditCategory.INFO_LEAKAGE,
        arguments={},
        verdict=verdict,
        justification="judged",
        severity=Severity.LOW,
    )
    tool_report = ToolReport(
        tool=ToolDefinition(name=tool, input_schema={"type": "object"}),
        cases=[TestCase(payload=_a_payload(AuditCategory.INFO_LEAKAGE), judge_result=result)],
    )
    return AuditReport(server_command=tool, tool_reports=[tool_report], provider_usage=usage)


def _a_refused_judgment(tool: str) -> MissedModelCall:
    return MissedModelCall(
        tool_name=tool,
        kind=ModelCallKind.JUDGMENT,
        cause=MissedCallCause.PROVIDER_REFUSAL,
        detail="refused",
    )


def _a_payload(category: AuditCategory) -> AuditPayload:
    return AuditPayload(category=category, description="a case", arguments={})
