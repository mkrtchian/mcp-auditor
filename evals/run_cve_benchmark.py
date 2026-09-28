import argparse
import asyncio
import json
import subprocess
import sys
import traceback
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path

from rich.console import Console

from evals import cve_grammar, cve_units
from evals import eval_display as display
from evals.baseline import BaselineStatus, fingerprint_sources
from evals.concurrency import positive_int
from evals.cve_audit import audit_target
from evals.cve_baseline import CVE_BASELINE_DIRECTORY, CVERunConditions
from evals.cve_calibration import calibrate_all
from evals.cve_grammar import RunGrade
from evals.cve_oracle import (
    CVEBenchmarkReport,
    CVEResult,
    not_run,
    out_of_scope_results,
    render_markdown,
    result_for,
)
from evals.cve_session import CVEHarness, CVEOptions, CVESessionResult, run_gated
from evals.cve_targets import (
    CVE_TARGETS,
    OUT_OF_SCOPE_CVES,
    CVETarget,
    OutOfScopeCVE,
    image_tag,
)
from evals.eval_session import RECORDING_REFUSED, Refused, read_tree
from mcp_auditor.config import Settings, load_settings

CVE_RUNS = 3
CVE_TEST_BUDGET = 10
CVE_CONCURRENCY = 6
DEFAULT_REPORT_PATH = "output/cve_report.json"
NOT_COMPARABLE_EXIT = 3
CRASHED_EXIT = 4
# Fingerprinted in this fixed order, so the fingerprint names one version of the grammar.
GRAMMAR_PATHS = (Path(cve_grammar.__file__), Path(cve_units.__file__))

EXPECTED_IMAGES = tuple(
    image_tag(name) for name in dict.fromkeys(n for t in CVE_TARGETS for n in t.images)
)
_BUILD_HINT = "run `docker compose -f evals/docker/compose.yml build`"

console = Console()


_NEXT_STEP = {
    BaselineStatus.EXPLORATORY: (
        "Run --record-baseline again now, at this commit and on these images, to confirm them."
    ),
    BaselineStatus.CONFIRMED: "Commit evals/baselines/cve/ by hand.",
}


def main() -> None:
    args = _parse_args()
    graded = _filter_by_cve(CVE_TARGETS, args.cve)
    tracked = _filter_by_cve(OUT_OF_SCOPE_CVES, args.cve)
    _reject_unknown_cves(args.cve, {t.cve_id for t in (*graded, *tracked)})
    refusal = _flag_refusal(args)
    if refusal:
        display.print_refusal(RECORDING_REFUSED if args.record_baseline else "Refused.", [refusal])
        sys.exit(NOT_COMPARABLE_EXIT)

    # Says nothing of detection nor of the fixtures, so a crash in every mode.
    if not _preflight_ok():
        sys.exit(CRASHED_EXIT)

    if args.calibrate:
        sys.exit(0 if asyncio.run(calibrate_all(graded, ci=args.ci)) else 1)

    try:
        code = asyncio.run(_run_graded(args, graded, tracked))
    except Refused as refused:
        display.print_refusal(refused.title, refused.reasons)
        code = NOT_COMPARABLE_EXIT
    except Exception:
        traceback.print_exc()
        code = CRASHED_EXIT
    sys.exit(code)


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run the CVE validation benchmark")
    parser.add_argument("--runs", type=int, default=CVE_RUNS)
    parser.add_argument("--budget", type=int, default=CVE_TEST_BUDGET)
    parser.add_argument("--report", type=str, default=DEFAULT_REPORT_PATH)
    parser.add_argument(
        "--concurrency",
        type=positive_int,
        default=CVE_CONCURRENCY,
        help="Audits in flight at once; 1 runs them one after the other.",
    )
    parser.add_argument(
        "--calibrate",
        action="store_true",
        help=(
            "No-LLM exploit and benign call per target; "
            "confirms each fixture is live and its benign call is clean."
        ),
    )
    parser.add_argument(
        "--cve",
        action="append",
        metavar="CVE-ID",
        help="Run only these CVE ids (repeatable); default: all.",
    )
    parser.add_argument(
        "--ci",
        action="store_true",
        help="Skip fixtures marked CI-unstable (ci_skip_reason); for the CI calibration gate.",
    )
    parser.add_argument(
        "--record-baseline",
        action="store_true",
        help=(
            "Record one file per target in evals/baselines/cve/ from a clean tree: run it twice "
            "at one commit on the local images (exploratory, then confirmed), commit by hand."
        ),
    )
    parser.add_argument(
        "--ungated",
        action="store_true",
        help="Run and report without comparing to evals/baselines/cve/ (exit 0).",
    )
    return parser.parse_args()


def _flag_refusal(args: argparse.Namespace) -> str | None:
    if args.calibrate and (args.record_baseline or args.ungated):
        return "--calibrate runs no audit: it neither records nor gates"
    if args.record_baseline and args.ungated:
        return "--record-baseline cannot run --ungated: a baseline records the conditions it gates"
    return None


async def _run_graded(
    args: argparse.Namespace, graded: list[CVETarget], tracked: list[OutOfScopeCVE]
) -> int:
    conditions = _run_conditions(load_settings(), args.runs, args.budget)
    options = CVEOptions(graded, conditions, args.ungated, args.record_baseline)
    session = await run_gated(options, _harness(args.budget, args.concurrency))
    results = [_result(target, session.grades[target.cve_id], args.budget) for target in graded]
    results.extend(out_of_scope_results(tracked))
    report = CVEBenchmarkReport(
        conditions=conditions,
        concurrency=args.concurrency,
        results=results,
        gate=session.gate,
        recording_refused=session.recording_refused,
    )
    _write_reports(report, Path(args.report))
    _print_session(session)
    if session.recording_refused:
        display.print_refusal(RECORDING_REFUSED, session.recording_refused)
        return NOT_COMPARABLE_EXIT
    return session.exit_code


def _result(target: CVETarget, grades: list[RunGrade], budget: int) -> CVEResult:
    return not_run(target) if not grades else result_for(target, grades, budget)


def _harness(budget: int, concurrency: int) -> CVEHarness:
    return CVEHarness(
        audit=audit_target(budget, concurrency),
        baselines=CVE_BASELINE_DIRECTORY,
        read_tree=read_tree,
        image_ids=_image_ids,
        clock=lambda: datetime.now(UTC).isoformat(),
    )


def _image_ids(names: Sequence[str]) -> dict[str, str]:
    return {
        name: subprocess.run(
            ["docker", "image", "inspect", "--format", "{{.Id}}", image_tag(name)],
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
        for name in names
    }


def _print_session(session: CVESessionResult) -> None:
    if session.gate is None:
        console.print("[yellow]Ungated run: nothing compared to evals/baselines/cve/.[/yellow]")
    else:
        console.print(f"Gate: [bold]{session.gate.verdict.value}[/bold].")
    for orphan in session.orphans:
        console.print(f"[yellow]Orphaned baseline file, not compared:[/yellow] {orphan}")
    for written in session.written:
        path = CVE_BASELINE_DIRECTORY / f"{written.cve_id}.json"
        console.print(f"[green]Baseline recorded ({written.status}) to {path}.[/green]")
        if written.leaves_gated_set:
            console.print(f"  {written.cve_id} leaves the gated set.")
    # A recording can confirm some files and start others, and each status has its next step.
    for status in dict.fromkeys(written.status for written in session.written):
        console.print(_NEXT_STEP[status])


def _run_conditions(settings: Settings, runs: int, budget: int) -> CVERunConditions:
    return CVERunConditions(
        runs=runs,
        budget=budget,
        tools_filtered=True,
        provider=settings.provider,
        model=settings.resolve_model(),
        judge_model=settings.resolve_judge_model(),
        reasoning=settings.resolve_reasoning(settings.resolve_model()),
        judge_reasoning=settings.resolve_reasoning(settings.resolve_judge_model()),
        grammar_fingerprint=fingerprint_sources([path.read_text() for path in GRAMMAR_PATHS]),
    )


def _write_reports(report: CVEBenchmarkReport, report_path: Path) -> None:
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(json.dumps(report.model_dump(mode="json"), indent=2))
    markdown = render_markdown(report)
    report_path.with_suffix(".md").write_text(markdown)

    console.print(markdown)
    console.print(f"Report written to {report_path}")


def _preflight_ok() -> bool:
    if not _docker_ready():
        console.print(f"[red]Docker daemon unreachable.[/red] Start Docker, then {_BUILD_HINT}.")
        return False
    missing = [image for image in EXPECTED_IMAGES if not _image_exists(image)]
    if missing:
        console.print(f"[red]Missing images:[/red] {', '.join(missing)}. To build: {_BUILD_HINT}.")
        return False
    _warn_if_pids_limit_discarded()
    return True


def _warn_if_pids_limit_discarded() -> None:
    # Docker does not fail on a limit its host cannot enforce, it warns on
    # stderr and runs without it, and the launchers discard stderr.
    result = subprocess.run(
        ["docker", "info", "--format", "{{.PidsLimit}}"],
        check=False,
        capture_output=True,
        text=True,
    )
    if result.stdout.strip() == "false":
        console.print(
            "[yellow]This Docker host cannot enforce --pids-limit, targets run without it.[/yellow]"
        )


def _docker_ready() -> bool:
    return _docker_command_succeeds(["docker", "info"])


def _image_exists(image: str) -> bool:
    return _docker_command_succeeds(["docker", "image", "inspect", image])


def _docker_command_succeeds(command: list[str]) -> bool:
    try:
        return subprocess.run(command, capture_output=True).returncode == 0
    except OSError:
        return False


def _filter_by_cve[T: (CVETarget, OutOfScopeCVE)](items: list[T], ids: list[str] | None) -> list[T]:
    if not ids:
        return items
    wanted = set(ids)
    return [item for item in items if item.cve_id in wanted]


def _reject_unknown_cves(ids: list[str] | None, known: set[str]) -> None:
    if not ids:
        return
    unknown = set(ids) - known
    if unknown:
        console.print(f"[red]Unknown CVE id(s):[/red] {', '.join(sorted(unknown))}")
        sys.exit(2)


if __name__ == "__main__":
    main()
