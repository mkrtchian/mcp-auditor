from collections.abc import Sequence

from evals.cve.nuisance.admission.admission import AdmittedServer
from evals.cve.nuisance.audit import DroppedRun, NuisanceAudit
from evals.cve.nuisance.holdout_run_status import RunCount, run_status_line

type FinishedRun = tuple[AdmittedServer, NuisanceAudit | DroppedRun]


def runs_announced(
    announced: list[str], *, together: Sequence[FinishedRun], alone: Sequence[FinishedRun]
) -> None:
    """Each run announced once as it finishes, the runs done rising from 1 to the total: the
    runs played together in any order, then the runs played alone in their order."""
    total = len(together) + len(alone)
    assert len(announced) == total
    pending = list(together)
    for done, line in enumerate(announced[: len(together)], start=1):
        lines = [
            run_status_line(server, outcome, RunCount(done, total)) for server, outcome in pending
        ]
        assert line in lines
        del pending[lines.index(line)]
    assert announced[len(together) :] == [
        run_status_line(server, outcome, RunCount(done, total))
        for done, (server, outcome) in enumerate(alone, start=len(together) + 1)
    ]
