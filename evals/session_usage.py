import logging
from dataclasses import dataclass, field

from pydantic import BaseModel

from mcp_auditor.domain.model_calls import MissedCallCause, MissedModelCall
from mcp_auditor.domain.models import AuditReport, ProviderUsage


class ThrottledAudit(Exception):
    """An audit throttled by the model provider past every retry, which says nothing about
    detection: the evals read it as infrastructure noise, not as a result."""


def raise_if_throttled(report: AuditReport) -> None:
    throttled = [
        f"{missed.tool_name}: {missed.kind}, {missed.detail}"
        for missed in throttled_model_calls(report)
    ]
    if throttled:
        raise ThrottledAudit(
            "throttled by the model provider past every retry: " + "; ".join(throttled)
        )


def throttled_model_calls(report: AuditReport) -> list[MissedModelCall]:
    return [
        missed
        for missed in report.missed_model_calls
        if missed.cause is MissedCallCause.PROVIDER_THROTTLED
    ]


def quiet_throttle_waits() -> None:
    """Many audits in flight would print a line per wait, and each eval prints the throttle
    total already."""
    logging.getLogger("mcp_auditor.throttling").setLevel(logging.ERROR)


class UsageBreakdown(BaseModel):
    """An audit's usage by phase. The channels overlap (the chain judgment counts in chain and
    judge), so the total is never their sum."""

    total: ProviderUsage = ProviderUsage()
    chain: ProviderUsage = ProviderUsage()
    judge: ProviderUsage = ProviderUsage()

    @classmethod
    def from_report(cls, report: AuditReport) -> "UsageBreakdown":
        return cls(total=report.provider_usage, chain=report.chain_usage, judge=report.judge_usage)

    def add(self, other: "UsageBreakdown") -> "UsageBreakdown":
        return UsageBreakdown(
            total=self.total.add(other.total),
            chain=self.chain.add(other.chain),
            judge=self.judge.add(other.judge),
        )


@dataclass
class SessionThrottles:
    requests: int = 0
    usage: ProviderUsage = field(default_factory=ProviderUsage)
    by_target: dict[str, UsageBreakdown] = field(default_factory=dict[str, UsageBreakdown])

    def count(self, report: AuditReport, target_id: str | None = None) -> int:
        """Every report counted is billed, an incomplete attempt's and a retest's included."""
        if target_id is not None:
            billed = self.by_target.get(target_id, UsageBreakdown())
            self.by_target[target_id] = billed.add(UsageBreakdown.from_report(report))
        return self.count_usage(report.provider_usage)

    def count_usage(self, usage: ProviderUsage) -> int:
        self.requests += usage.throttled_requests
        self.usage = self.usage.add(usage)
        return usage.throttled_requests
