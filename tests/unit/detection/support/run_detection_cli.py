from collections.abc import Callable

import pytest

from evals import run_detection
from evals.cve.detection.session import DetectionSessionResult
from evals.cve.detection.session_model import AuditTarget, DetectionHarness, DetectionOptions
from evals.eval_session import TreeState
from evals.metrics import SessionThrottles
from mcp_auditor.domain.models import AuditReport, ProviderUsage
from tests.fakes import FakeContainerSweep

BILLED_FLAW = "CVE-billed"
PRICED_MODEL = "gpt-6-luna"
RECORDED_FLAW = "CVE-2025-53109"


def exit_code_of(monkeypatch: pytest.MonkeyPatch, *flags: str) -> object:
    monkeypatch.setattr("sys.argv", ["run_detection", *flags])
    with pytest.raises(SystemExit) as exit_:
        run_detection.main()
    return exit_.value.code


def a_sweep_finding(monkeypatch: pytest.MonkeyPatch, *running: str) -> FakeContainerSweep:
    """The containers left running that the final sweep lists, once."""
    containers = FakeContainerSweep(list(running))
    monkeypatch.setattr(run_detection, "DOCKER_SWEEP", containers.sweep)
    return containers


def a_session_under_priced_models(
    monkeypatch: pytest.MonkeyPatch,
    audit_target: Callable[..., AuditTarget] | None = None,
    dirty: bool = False,
) -> None:
    """A graded session that reaches no Docker and audits no target, under a priced generator
    and judge."""
    monkeypatch.setenv("MCP_AUDITOR_PROVIDER", "openai")
    monkeypatch.setenv("MCP_AUDITOR_MODEL", PRICED_MODEL)
    monkeypatch.setenv("MCP_AUDITOR_JUDGE_MODEL", PRICED_MODEL)
    monkeypatch.setattr(run_detection, "preflight_ok", lambda: True)
    monkeypatch.setattr(run_detection, "read_tree", lambda: TreeState("c0ffee", dirty=dirty))
    monkeypatch.setattr(run_detection, "audit_target", audit_target or a_billing_audit_target)
    monkeypatch.setattr(run_detection, "run_gated", a_session_auditing_nothing)


def a_billing_audit_target(
    budget: int, throttles: SessionThrottles, places: object, overrides: object = None
) -> AuditTarget:
    usage = ProviderUsage(input_tokens=500, output_tokens=50)
    throttles.count(
        AuditReport(server_command="test", tool_reports=[], provider_usage=usage), BILLED_FLAW
    )

    async def audit(target: object) -> None:
        return None

    return audit


async def a_session_auditing_nothing(
    options: DetectionOptions, harness: DetectionHarness
) -> DetectionSessionResult:
    return DetectionSessionResult(
        grades={target.flaw_id: [] for target in options.targets},
        audits=[],
        gate=None,
        not_run={},
        orphans=[],
        written=[],
        recording_refused=[],
        exit_code=0,
    )
