from dataclasses import replace

import pytest

import tests.unit.support.captured_console as captured_console
from evals.baseline import BaselineStatus
from evals.cve.detection.command_deps import DetectionCommandDeps
from evals.cve.detection.gate import DetectionGateResult
from evals.cve.detection.session import DetectionSessionResult
from evals.cve.detection.session_model import DetectionHarness, DetectionOptions
from evals.cve.detection.session_recording import WrittenBaseline
from evals.gate_outcome import GateOutcome
from tests.unit.detection.support.run_detection_cli import (
    RECORDED_FLAW,
    a_session_under_priced_models,
)


def a_captured_console(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> captured_console.CapturedOutput:
    return captured_console.a_captured_console(capsys, monkeypatch, width=400)


def a_recording_session_writing(
    monkeypatch: pytest.MonkeyPatch, status: BaselineStatus
) -> DetectionCommandDeps:
    """A green recording run that writes one baseline file with this status, reaching no Docker."""

    async def session(
        options: DetectionOptions, harness: DetectionHarness
    ) -> DetectionSessionResult:
        return DetectionSessionResult(
            grades={target.flaw_id: [] for target in options.targets},
            audits=[],
            gate=DetectionGateResult(outcome=GateOutcome.GREEN, reasons=[], targets=[]),
            not_run={},
            orphans=[],
            written=[WrittenBaseline(RECORDED_FLAW, status, leaves_gated_set=False)],
            recording_refused=[],
            exit_code=0,
        )

    return replace(a_session_under_priced_models(monkeypatch), session=session)
