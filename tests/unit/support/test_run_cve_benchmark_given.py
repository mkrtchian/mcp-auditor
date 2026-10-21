from collections.abc import Callable

import pytest

from evals import run_cve_benchmark
from evals.cve_session import CVESessionResult
from evals.cve_session_model import AuditTarget, CVEHarness, CVEOptions
from evals.eval_session import TreeState
from evals.metrics import SessionThrottles
from mcp_auditor.domain.models import AuditReport, ProviderUsage

BILLED_CVE = "CVE-billed"
PRICED_MODEL = "gpt-6-luna"


def exit_code_of(monkeypatch: pytest.MonkeyPatch, *flags: str) -> object:
    monkeypatch.setattr("sys.argv", ["run_cve_benchmark", *flags])
    with pytest.raises(SystemExit) as exit_:
        run_cve_benchmark.main()
    return exit_.value.code


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
    monkeypatch.setattr(run_cve_benchmark, "preflight_ok", lambda: True)
    monkeypatch.setattr(run_cve_benchmark, "read_tree", lambda: TreeState("c0ffee", dirty=dirty))
    monkeypatch.setattr(run_cve_benchmark, "audit_target", audit_target or a_billing_audit_target)
    monkeypatch.setattr(run_cve_benchmark, "run_gated", a_session_auditing_nothing)


def a_billing_audit_target(
    budget: int, throttles: SessionThrottles, places: object, overrides: object = None
) -> AuditTarget:
    usage = ProviderUsage(input_tokens=500, output_tokens=50)
    throttles.count(AuditReport(target="test", tool_reports=[], provider_usage=usage), BILLED_CVE)

    async def audit(target: object) -> None:
        return None

    return audit


def an_audit_target_recording(forced: list[object]) -> Callable[..., AuditTarget]:
    def audit_target(
        budget: int, throttles: SessionThrottles, places: object, overrides: object = None
    ) -> AuditTarget:
        forced.append(overrides)
        return a_billing_audit_target(budget, throttles, places)

    return audit_target


async def a_session_auditing_nothing(options: CVEOptions, harness: CVEHarness) -> CVESessionResult:
    return CVESessionResult(
        grades={target.cve_id: [] for target in options.targets},
        audits=[],
        gate=None,
        not_run={},
        orphans=[],
        written=[],
        recording_refused=[],
        exit_code=0,
    )


async def a_session_that_crashes_if_started(
    options: CVEOptions, harness: CVEHarness
) -> CVESessionResult:
    # main turns any exception into exit 4, so an exit 3 proves the session never started.
    raise AssertionError("the session must not start")
