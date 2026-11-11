from collections.abc import Callable
from io import StringIO

import pytest

import tests.unit.support.test_eval_display_given as display_given
from evals import run_detection
from evals.baseline import BaselineStatus
from evals.cve.detection import console as detection_console
from evals.cve.detection import no_llm_modes, recording_console
from evals.cve.detection.calibration_check_exit import CalibrationCheckDeps
from evals.cve.detection.gate import DetectionGateResult
from evals.cve.detection.session import DetectionSessionResult
from evals.cve.detection.session_model import AuditTarget, DetectionHarness, DetectionOptions
from evals.cve.detection.session_recording import WrittenBaseline
from evals.eval_session import TreeState
from evals.gate_outcome import GateOutcome
from evals.metrics import SessionThrottles
from mcp_auditor.domain.models import AuditReport, ProviderUsage
from tests.fakes import FakeContainerSweep
from tests.unit.support.test_detection_calibration_check_exit_given import deps_with

BILLED_CVE = "CVE-billed"
PRICED_MODEL = "gpt-6-luna"
RECORDED_CVE = "CVE-2025-53109"


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


def a_calibration(monkeypatch: pytest.MonkeyPatch, *, raises: bool = False) -> None:
    """Past the preflight, every fixture admitted and live, or a configuration error."""
    monkeypatch.setattr(run_detection, "preflight_ok", lambda: True)

    def default_calibration_check_deps(*_args: object, **_kwargs: object) -> CalibrationCheckDeps:
        return deps_with(raises=raises)

    monkeypatch.setattr(
        no_llm_modes, "default_calibration_check_deps", default_calibration_check_deps
    )


def a_survey(monkeypatch: pytest.MonkeyPatch, *, raises: bool = False) -> None:
    monkeypatch.setattr(run_detection, "preflight_ok", lambda: True)

    async def survey_all(*_args: object, **_kwargs: object) -> None:
        if raises:
            raise ValueError("a kept id with no record")

    monkeypatch.setattr(no_llm_modes, "survey_all", survey_all)


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


def a_captured_console(monkeypatch: pytest.MonkeyPatch) -> StringIO:
    return display_given.a_captured_console(
        monkeypatch, run_detection, detection_console, recording_console, width=400
    )


def a_recording_session_writing(monkeypatch: pytest.MonkeyPatch, status: BaselineStatus) -> None:
    """A green recording run that writes one baseline file with this status, reaching no Docker."""
    a_session_under_priced_models(monkeypatch)

    async def check_layouts_and_routes(*_args: object, **_kwargs: object) -> list[str]:
        return []

    async def session(
        options: DetectionOptions, harness: DetectionHarness
    ) -> DetectionSessionResult:
        return DetectionSessionResult(
            grades={target.flaw_id: [] for target in options.targets},
            audits=[],
            gate=DetectionGateResult(outcome=GateOutcome.GREEN, reasons=[], targets=[]),
            not_run={},
            orphans=[],
            written=[WrittenBaseline(RECORDED_CVE, status, leaves_gated_set=False)],
            recording_refused=[],
            exit_code=0,
        )

    monkeypatch.setattr(run_detection, "check_layouts_and_routes", check_layouts_and_routes)
    monkeypatch.setattr(run_detection, "run_gated", session)


def a_billing_audit_target(
    budget: int, throttles: SessionThrottles, places: object, overrides: object = None
) -> AuditTarget:
    usage = ProviderUsage(input_tokens=500, output_tokens=50)
    throttles.count(
        AuditReport(server_command="test", tool_reports=[], provider_usage=usage), BILLED_CVE
    )

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


async def a_session_that_crashes_if_started(
    options: DetectionOptions, harness: DetectionHarness
) -> DetectionSessionResult:
    # main turns any exception into exit 4, so an exit 3 proves the session never started.
    raise AssertionError("the session must not start")
