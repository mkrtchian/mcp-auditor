from typing import Any

from evals.probe.analysis import CallOutcome, ProbeObservation
from evals.probe.corpus import Role
from mcp_auditor.domain.models import ProviderUsage


def an_observation(
    role: Role = "main",
    schema_name: str = "TestCaseBatch",
    seconds: float = 1.0,
    outcome: CallOutcome = CallOutcome.PARSED,
    **changes: Any,
) -> ProbeObservation:
    return ProbeObservation(
        candidate="candidate",
        call_id=f"honeypot/{schema_name}/000",
        schema_name=schema_name,
        role=role,
        seconds=seconds,
        usage=changes.pop("usage", ProviderUsage()),
        outcome=outcome,
        coverage_gap=changes.pop("coverage_gap", None),
        **changes,
    )
