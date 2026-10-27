from datetime import date
from io import StringIO

import pytest
from rich.console import Console

import tests.unit.support.test_cve_oracle_given as oracle_given
from evals import cve_console, eval_display
from evals.cve_gate import CVEGateResult, CVEGateVerdict, TargetComparison, TargetOutcome
from evals.cve_grammar import CVEStatus
from evals.cve_oracle import CVEBenchmarkReport, CVEResult, UngradedStatus

DETECTED_CVE = "CVE-2025-53109"
NOT_RUN_CVE = "CVE-2025-68143"


def a_captured_console(monkeypatch: pytest.MonkeyPatch) -> StringIO:
    buffer = StringIO()
    shared = Console(file=buffer, width=200)
    monkeypatch.setattr(cve_console, "console", shared)
    monkeypatch.setattr(eval_display, "console", shared)
    return buffer


def a_gated_report(**update: object) -> CVEBenchmarkReport:
    report = oracle_given.a_benchmark_report(
        [oracle_given.a_cve_result(DETECTED_CVE, CVEStatus.DETECTED, detected_runs=3)]
    )
    return report.model_copy(update={"gate": oracle_given.a_red_gate(), **update})


def an_ungated_report(**update: object) -> CVEBenchmarkReport:
    return a_gated_report(gate=None, **update)


def a_not_run_result(conditions: list[str]) -> CVEResult:
    return CVEResult(
        cve_id=NOT_RUN_CVE,
        severity="7.5 HIGH",
        note="test note",
        status=UngradedStatus.NOT_RUN,
        not_run_conditions=conditions,
    )


def a_report_with_a_not_run_target(conditions: list[str], gated: bool) -> CVEBenchmarkReport:
    report = a_gated_report() if gated else an_ungated_report()
    return report.model_copy(update={"results": [*report.results, a_not_run_result(conditions)]})


def a_report_gated_on_a_detail(detail: str) -> CVEBenchmarkReport:
    comparison = TargetComparison(
        cve_id=NOT_RUN_CVE,
        outcome=TargetOutcome.NOT_RUN,
        candidate_runs=[],
        detail=detail,
    )
    gate = CVEGateResult(verdict=CVEGateVerdict.NOT_COMPARABLE, reasons=[], targets=[comparison])
    return a_gated_report(gate=gate)


def a_priced_ungated_report() -> CVEBenchmarkReport:
    return an_ungated_report(
        costs=[oracle_given.a_target_cost(DETECTED_CVE)], prices_as_of=date(2026, 10, 1)
    )
