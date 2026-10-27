from io import StringIO
from pathlib import Path

import pytest
from rich.console import Console

import tests.unit.support.test_holdout_census_given as census_given
import tests.unit.support.test_nuisance_admission_given as admission_given
from evals import eval_display, nuisance_gate_command, nuisance_gate_console
from evals.baseline import BaselineStatus
from evals.eval_session import TreeState
from evals.gate_verdict import GateVerdict
from evals.nuisance_gate import NuisanceGateResult
from evals.nuisance_gate_baseline import NuisanceGateConditions
from evals.nuisance_gate_session_model import (
    NuisanceGateHarness,
    NuisanceGateOptions,
    NuisanceGateSession,
    WrittenBaseline,
)
from tests.unit.support.test_nuisance_gate_baseline_given import conditions
from tests.unit.support.test_nuisance_gate_session_given import KUBERNETES, a_harness, scripted

GATE_SERVER = KUBERNETES.server_package


def a_gate_set_of_one_server(tmp_path: Path) -> list[str]:
    """The census and admission arguments of a gate whose one server is GATE_SERVER."""
    census = census_given.with_a_cve_of(census_given.a_census(), "CVE-2025-53355", GATE_SERVER)
    admitted = admission_given.admitting_the_server_of(
        "CVE-2025-53355", GATE_SERVER, "kubernetes-nuisance"
    )
    return [
        "--census",
        str(census_given.written(tmp_path, census)),
        "--admission",
        str(admission_given.written(tmp_path, admitted)),
        "--report",
        str(tmp_path / "nuisance_gate_report.json"),
    ]


def a_captured_console(monkeypatch: pytest.MonkeyPatch) -> StringIO:
    buffer = StringIO()
    shared = Console(file=buffer, width=400)
    for module in (nuisance_gate_command, nuisance_gate_console, eval_display):
        monkeypatch.setattr(module, "console", shared)
    return buffer


def a_green_recording_writing(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, status: BaselineStatus
) -> None:
    """A gate run that audits nothing and records one baseline file with this status, reaching
    no Docker and no LLM."""

    async def session(
        options: NuisanceGateOptions, harness: NuisanceGateHarness
    ) -> NuisanceGateSession:
        return NuisanceGateSession(
            audits=[],
            gate=NuisanceGateResult(verdict=GateVerdict.GREEN, reasons=[], servers=[]),
            not_run={},
            orphans=[],
            written=[WrittenBaseline(GATE_SERVER, status, leaves_gated_set=False)],
            recording_refused=[],
            throttled_requests=0,
            exit_code=0,
        )

    def gate_conditions(
        _settings: object, _conditions: object, runs: int
    ) -> NuisanceGateConditions:
        return conditions(runs)

    def default_harness(*_: object) -> NuisanceGateHarness:
        return a_harness(tmp_path, scripted({}))

    monkeypatch.setattr(nuisance_gate_command, "read_tree", lambda: TreeState("c0ffee", False))
    monkeypatch.setattr(nuisance_gate_command, "gate_conditions", gate_conditions)
    monkeypatch.setattr(nuisance_gate_command, "default_harness", default_harness)
    monkeypatch.setattr(nuisance_gate_command, "run_gate", session)
