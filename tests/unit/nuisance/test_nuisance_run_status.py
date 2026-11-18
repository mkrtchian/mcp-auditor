"""The status line the nuisance run prints as each run of a server finishes. No Docker, no LLM."""

import pytest

import tests.unit.nuisance.support.test_nuisance_run_given as run_given
from evals.cve.nuisance.audit import DroppedRun, NuisanceAudit
from evals.cve.nuisance.results import NotRunCause
from evals.cve.nuisance.run_status import RunCount, run_status_line
from mcp_auditor.domain.models import MissCause

SERVER = run_given.a_server("npm:pkg")


@pytest.mark.parametrize(
    ("outcome", "line"),
    [
        (run_given.an_audit(True), "npm:pkg: flagged [1/4 runs]"),
        (run_given.an_audit(False), "npm:pkg: not flagged [1/4 runs]"),
        (
            run_given.an_audit(False, missed=MissCause.UNREADABLE_ANSWER),
            "npm:pkg: not flagged, incomplete [1/4 runs]",
        ),
        (
            DroppedRun(NotRunCause.LAUNCH_FAILURE),
            "npm:pkg: run dropped (a run failed to launch after retries) [1/4 runs]",
        ),
    ],
    ids=["flagged", "not flagged", "incomplete", "dropped"],
)
def test_the_line_names_the_run_status_and_the_runs_done(
    outcome: NuisanceAudit | DroppedRun, line: str
):
    assert run_status_line(SERVER, outcome, RunCount(done=1, total=4)) == line
