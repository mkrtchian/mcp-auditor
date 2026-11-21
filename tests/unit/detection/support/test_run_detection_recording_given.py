from io import StringIO

import pytest

import tests.unit.evals.support.test_eval_display_given as display_given
from evals import run_detection
from evals.baseline import BaselineStatus
from evals.cve.detection import console as detection_console
from evals.cve.detection import recording_console
from evals.cve.detection.gate import DetectionGateResult
from evals.cve.detection.session import DetectionSessionResult
from evals.cve.detection.session_model import DetectionHarness, DetectionOptions
from evals.cve.detection.session_recording import WrittenBaseline
from evals.gate_outcome import GateOutcome
from tests.unit.detection.support.run_detection_cli import (
    RECORDED_FLAW,
    a_session_under_priced_models,
)


def a_captured_console(monkeypatch: pytest.MonkeyPatch) -> StringIO:
    return display_given.a_captured_console(
        monkeypatch, run_detection, detection_console, recording_console, width=400
    )


def a_recording_session_writing(monkeypatch: pytest.MonkeyPatch, status: BaselineStatus) -> None:
    """A green recording run that writes one baseline file with this status, reaching no Docker."""
    a_session_under_priced_models(monkeypatch)

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

    monkeypatch.setattr(run_detection, "run_gated", session)
