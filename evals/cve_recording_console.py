"""What a CVE recording prints after the summary: orphaned files, written baselines, next steps."""

from collections.abc import Sequence

from rich.markup import escape

from evals.baseline import BaselineStatus
from evals.cve_baseline import CVE_BASELINE_DIRECTORY
from evals.cve_session import CVESessionResult
from evals.eval_display import console

_BASELINES = "evals/baselines/cve/"
_RECORD_COMMAND = "uv run python -m evals.run_cve_benchmark --record-baseline"


def print_recording(session: CVESessionResult, recorded_flags: Sequence[str]) -> None:
    for orphan in session.orphans:
        console.print(f"[yellow]Orphaned baseline file, not compared:[/yellow] {escape(orphan)}")
    for written in session.written:
        path = CVE_BASELINE_DIRECTORY / f"{written.cve_id}.json"
        console.print(f"[green]Baseline recorded ({written.status}) to {path}.[/green]")
        if written.leaves_gated_set:
            console.print(f"  {written.cve_id} leaves the gated set.")
    # A recording can confirm some files and start others, and each status has its next step.
    for status in dict.fromkeys(written.status for written in session.written):
        console.print(_next_step(status, recorded_flags))


def _next_step(status: BaselineStatus, recorded_flags: Sequence[str]) -> str:
    if status == BaselineStatus.CONFIRMED:
        return f"Commit {_BASELINES} by hand."
    command = " ".join([_RECORD_COMMAND, *recorded_flags])
    return (
        f"Run {command} again now, at this commit and on these images, to confirm it. "
        f"Commit {_BASELINES} by hand once confirmed."
    )
