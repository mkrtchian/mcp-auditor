from io import StringIO

import pytest
from rich.console import Console

from evals import eval_display, nuisance_gate_console
from evals.nuisance_gate_report import NuisanceGateReport
from tests.unit.support.test_nuisance_gate_report_given import (
    a_held_server_beside_a_regression,
    a_not_gated_server_with_an_alarm,
    a_report_of,
)
from tests.unit.support.test_nuisance_gate_session_given import KUBERNETES


def a_captured_console(monkeypatch: pytest.MonkeyPatch) -> StringIO:
    buffer = StringIO()
    shared = Console(file=buffer, width=200)
    monkeypatch.setattr(nuisance_gate_console, "console", shared)
    monkeypatch.setattr(eval_display, "console", shared)
    return buffer


def a_red_report(throttled_requests: int = 0) -> NuisanceGateReport:
    return a_report_of(a_held_server_beside_a_regression(), throttled_requests)


def a_not_gated_report() -> NuisanceGateReport:
    return a_report_of(a_not_gated_server_with_an_alarm())


def a_report_that_recorded() -> NuisanceGateReport:
    return a_red_report().model_copy(
        update={
            "written": [f"{KUBERNETES.server_package}: recorded (exploratory)"],
            "orphans": ["npm-gone.json"],
            "recording_refused": ["the tree changed during the runs"],
        }
    )


def a_report_with_a_server_not_run(reason: str) -> NuisanceGateReport:
    return a_red_report().model_copy(update={"not_run": {KUBERNETES.server_package: reason}})
