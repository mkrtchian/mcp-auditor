from evals.cve.nuisance.gate.gate_report import NuisanceGateReport
from tests.unit.nuisance.gate.support.nuisance_gate_reports import (
    a_held_server_beside_a_regression,
    a_report_of,
    an_inconclusive_server_with_an_alarm,
)
from tests.unit.nuisance.gate.support.nuisance_gate_sessions import KUBERNETES


def an_inconclusive_report() -> NuisanceGateReport:
    return a_report_of(an_inconclusive_server_with_an_alarm())


def a_report_that_recorded() -> NuisanceGateReport:
    return a_red_report().model_copy(
        update={
            "written": [f"{KUBERNETES.server_package}: recorded (unconfirmed)"],
            "orphans": ["npm-gone.json"],
            "recording_refused": ["the tree changed during the runs"],
        }
    )


def a_red_report(throttled_requests: int = 0) -> NuisanceGateReport:
    return a_report_of(a_held_server_beside_a_regression(), throttled_requests)


def a_report_with_a_server_not_run(reason: str) -> NuisanceGateReport:
    return a_red_report().model_copy(update={"not_run": {KUBERNETES.server_package: reason}})
