from dataclasses import replace

import pytest

from evals import run_detection
from evals.cve.detection.calibration_check_exit import CalibrationCheckDeps
from evals.cve.detection.command_deps import DetectionCommandDeps
from evals.cve.detection.session import DetectionSessionResult
from evals.cve.detection.session_model import AuditTarget, DetectionHarness, DetectionOptions
from evals.cve.detection.survey import TargetSurvey
from evals.cve.detection.targets import Target
from evals.eval_session import TreeState
from evals.session_usage import SessionThrottles
from mcp_auditor.domain.models import AuditReport, ProviderUsage
from tests.fakes import FakeContainerSweep

BILLED_FLAW = "CVE-billed"
PRICED_MODEL = "gpt-6-luna"
RECORDED_FLAW = "CVE-2025-53109"


def exit_code_of(deps: DetectionCommandDeps, *flags: str) -> int:
    return run_detection.main(list(flags), deps)


def a_sweep_finding(*running: str) -> FakeContainerSweep:
    """The containers left running that the final sweep lists, once."""
    return FakeContainerSweep(list(running))


def a_session_under_priced_models(
    monkeypatch: pytest.MonkeyPatch, dirty: bool = False
) -> DetectionCommandDeps:
    """A graded session that reaches no Docker and audits no target, under a priced generator
    and judge."""
    monkeypatch.setenv("MCP_AUDITOR_PROVIDER", "openai")
    monkeypatch.setenv("MCP_AUDITOR_MODEL", PRICED_MODEL)
    monkeypatch.setenv("MCP_AUDITOR_JUDGE_MODEL", PRICED_MODEL)
    return replace(deps_reaching_nothing(), read_tree=lambda: TreeState("c0ffee", dirty=dirty))


def deps_reaching_nothing(sweep: FakeContainerSweep | None = None) -> DetectionCommandDeps:
    """Past the preflight on a clean tree, a session that audits nothing, and no calibration check
    or survey expected."""
    return DetectionCommandDeps(
        preflight=lambda: True,
        sweep=(sweep or FakeContainerSweep()).sweep,
        read_tree=lambda: TreeState("c0ffee", dirty=False),
        audit_target=a_billing_audit_target,
        session=a_session_auditing_nothing,
        calibration_check=_no_calibration_check,
        survey_one=_no_survey,
    )


def _no_calibration_check(
    concurrency: int, ci: bool, show_exploit_responses: bool
) -> CalibrationCheckDeps:
    raise AssertionError("this run runs no calibration check")


async def _no_survey(target: Target, places: object) -> TargetSurvey:
    raise AssertionError("this run surveys nothing")


def a_billing_audit_target(
    test_budget: int, throttles: SessionThrottles, places: object, overrides: object = None
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
