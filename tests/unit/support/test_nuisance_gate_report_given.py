from evals.nuisance_gate import ServerComparison, ServerOutcome, judge
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
            ),
            ServerComparison(
                server_package=KUBERNETES.server_package,
                outcome=ServerOutcome.REGRESSION,
                candidate_runs=regression,
                replays=[False, True, True, True, True],
            ),
        ],
        [],
    )
    return NuisanceGateSession(
        audits=[
            *_audits(FILESYSTEM.server_package, held),
            *_audits(KUBERNETES.server_package, regression),
        ],
        gate=gate,
        not_run={},
        orphans=[],
        written=[],
        recording_refused=[],
        exit_code=1,
    )


def a_report_of(session: NuisanceGateSession) -> NuisanceGateReport:
    return NuisanceGateReport(
        conditions=conditions(),
        commit="c0ffee",
        dirty=False,
        concurrency=9,
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
    end = lines.index("", start)
    return lines[start:end]


def _audits(package: str, flagged: list[bool]) -> list[GateAudit]:
    return [
        GateAudit(package, index, run.flagged, run.report)
        for index, run in enumerate(a_gate_run(each) for each in flagged)
    ]
