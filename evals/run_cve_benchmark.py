import argparse
import asyncio
import json
import os
import subprocess
import sys
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path

from rich.console import Console
from rich.markup import escape

from evals.cve_calibration import calibrate_all
from evals.cve_environments import Launch, connect
from evals.cve_oracle import (
    CVEResult,
    RunDetection,
    detect_in_report,
    not_run,
    out_of_scope_results,
    render_markdown,
    resolve_status,
)
from evals.cve_targets import CVE_TARGETS, OUT_OF_SCOPE_CVES, CVETarget, OutOfScopeCVE
from evals.metrics import blocked_reasons, refused_steps
from mcp_auditor.adapters.llm import create_judge_llm, create_llm
from mcp_auditor.config import load_settings
from mcp_auditor.domain.audited_server import AuditedServer
from mcp_auditor.domain.models import AttackContext, AuditReport
from mcp_auditor.domain.ports import MCPClientPort
from mcp_auditor.graph.builder import build_graph

CVE_RUNS = 3
CVE_TEST_BUDGET = 10
DEFAULT_REPORT_PATH = "output/cve_report.json"

EXPECTED_IMAGES = (
    "mcp-auditor-cve-filesystem:local",
    "mcp-auditor-cve-git:local",
    "mcp-auditor-cve-kubernetes:local",
    "mcp-auditor-cve-fetch:local",
    "mcp-auditor-cve-sentinel:local",
)
_BUILD_HINT = "run `docker compose -f evals/docker/compose.yml build`"

console = Console()


class LaunchError(Exception):
    """A pinned server failed to launch or install (infra, not a detection miss)."""


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the CVE validation benchmark")
    parser.add_argument("--runs", type=int, default=CVE_RUNS)
    parser.add_argument("--budget", type=int, default=CVE_TEST_BUDGET)
    parser.add_argument("--report", type=str, default=DEFAULT_REPORT_PATH)
    parser.add_argument(
        "--calibrate",
        action="store_true",
        help="No-LLM exploit and benign call per target; confirms each fixture is live.",
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
    args = parser.parse_args()

    graded = _filter_by_cve(CVE_TARGETS, args.cve)
    tracked = _filter_by_cve(OUT_OF_SCOPE_CVES, args.cve)
    _reject_unknown_cves(args.cve, {t.cve_id for t in (*graded, *tracked)})

    if not _preflight_ok():
        sys.exit(1)

    if args.calibrate:
        sys.exit(0 if asyncio.run(calibrate_all(graded, ci=args.ci)) else 1)

    results = asyncio.run(run_cve_benchmark(graded, args.budget, args.runs))
    results.extend(out_of_scope_results(tracked))
    _write_reports(results, Path(args.report))


def _write_reports(results: list[CVEResult], report_path: Path) -> None:
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(json.dumps([r.model_dump(mode="json") for r in results], indent=2))
    markdown = render_markdown(results)
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


async def run_cve_benchmark(targets: list[CVETarget], budget: int, runs: int) -> list[CVEResult]:
    results: list[CVEResult] = []
    for target in targets:
        detections: list[RunDetection] = []
        for _ in range(runs):
            try:
                with target.environment() as launch:
                    report = await _audit(launch, target, budget)
                    # Record before __exit__ fires so a best-effort teardown error
                    # cannot erase a completed run's detection.
                    detections.append(detect_in_report(target, report))
                    _print_incidents(target, report)
            except (LaunchError, subprocess.CalledProcessError) as exc:
                console.print(f"[yellow]{target.cve_id} run skipped:[/yellow] {exc}")
                continue
        results.append(
            not_run(target) if not detections else resolve_status(target, detections, budget)
        )
    return results


def _print_incidents(target: CVETarget, report: AuditReport) -> None:
    for reason in blocked_reasons(report):
        console.print(f"[yellow]{target.cve_id}: payload blocked, {reason}[/yellow]")
    for refused in refused_steps(report):
        console.print(
            f"[yellow]{target.cve_id}: refused by the model provider, {escape(refused)}[/yellow]"
        )


async def _audit(launch: Launch, target: CVETarget, budget: int) -> AuditReport:
    settings = load_settings()
    llm = create_llm(settings)
    judge_llm = create_judge_llm(settings)
    try:
        async with _silent_client(launch) as mcp_client:
            graph = build_graph(
                llm,
                AuditedServer(mcp_client),
                judge_llm=judge_llm,
                tools_filter=target.tools_filter,
            )
            result = await graph.ainvoke(  # pyright: ignore[reportUnknownMemberType]
                {
                    "target": f"{launch.command} {' '.join(launch.args)}",
                    "test_budget": budget,
                    "attack_context": AttackContext(),
                    "chain_budget": launch.chain_budget,
                    "max_chain_steps": launch.max_chain_steps,
                }
            )
            return result["audit_report"]
    except Exception as exc:
        raise LaunchError(str(exc)) from exc


@asynccontextmanager
async def _silent_client(launch: Launch) -> AsyncIterator[MCPClientPort]:
    with open(os.devnull, "w") as devnull:
        async with connect(launch, devnull) as client:
            yield client


if __name__ == "__main__":
    main()
