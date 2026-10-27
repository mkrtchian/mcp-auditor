import itertools

from evals.nuisance_gate import NuisanceGateResult, ServerComparison, ServerOutcome, judge
from evals.nuisance_gate_report import NuisanceGateReport, server_lines
from evals.nuisance_gate_session_model import GateAudit, NuisanceGateSession
from evals.nuisance_results import FigureExit
from tests.unit.support.test_nuisance_gate_baseline_given import conditions
from tests.unit.support.test_nuisance_gate_session_given import (
    FILESYSTEM,
    KUBERNETES,
    a_gate_run,
)

NOT_ADMITTED = "npm:mcp-fetch-server"
OUTSIDE = FigureExit("PyPI:mcp-server-git", "does not run over stdio")


def a_held_server_beside_a_regression() -> NuisanceGateSession:
    held = [False, False, False]
    regression = [True, False, False]
    gate = judge(
        [
            ServerComparison(
                server_package=FILESYSTEM.server_package,
                outcome=ServerOutcome.HELD,
                candidate_runs=held,
                baseline_runs=[False] * 6,
            ),
            ServerComparison(
                server_package=KUBERNETES.server_package,
                outcome=ServerOutcome.REGRESSION,
                candidate_runs=regression,
                baseline_runs=[False] * 6,
                replays=[False, True, True, True, True],
            ),
        ],
        [],
    )
    return _session(
        [
            *_audits(FILESYSTEM.server_package, held),
            *_audits(KUBERNETES.server_package, regression),
        ],
        gate,
    )


def a_not_gated_server_with_an_alarm() -> NuisanceGateSession:
    runs = [True, False, False]
    comparison = ServerComparison(
        server_package=KUBERNETES.server_package,
        outcome=ServerOutcome.NOT_GATED,
        candidate_runs=runs,
        baseline_runs=[False] * 5 + [True],
        detail=FLAGGED_IN_BASELINE,
    )
    return _session(_audits(KUBERNETES.server_package, runs), judge([comparison], []))


FLAGGED_IN_BASELINE = "flagged in 1 of 6 baseline runs"


def _session(audits: list[GateAudit], gate: NuisanceGateResult) -> NuisanceGateSession:
    return NuisanceGateSession(
        audits=audits,
        gate=gate,
        not_run={},
        orphans=[],
        written=[],
        recording_refused=[],
        throttled_requests=0,
        exit_code=1,
    )


def a_report_of(session: NuisanceGateSession, throttled_requests: int = 0) -> NuisanceGateReport:
    return NuisanceGateReport(
        conditions=conditions(),
        commit="c0ffee",
        dirty=False,
        concurrency=9,
        throttled_requests=throttled_requests,
        servers=server_lines(session, [FILESYSTEM, KUBERNETES]),
        not_run=session.not_run,
        not_admitted=[NOT_ADMITTED],
        outside_gate=[OUTSIDE],
        orphans=session.orphans,
        gate=session.gate,
        written=[],
        recording_refused=session.recording_refused,
    )


def row_of(markdown: str, package: str) -> str:
    [row] = [line for line in markdown.splitlines() if line.startswith(f"| {package} |")]
    return row


def section(markdown: str, header: str) -> list[str]:
    lines = markdown.splitlines()
    start = lines.index(header) + 1
    return list(itertools.takewhile(bool, lines[start:]))


def _audits(package: str, flagged: list[bool]) -> list[GateAudit]:
    return [
        GateAudit(package, index, run.flagged, run.report)
        for index, run in enumerate(a_gate_run(each) for each in flagged)
    ]
