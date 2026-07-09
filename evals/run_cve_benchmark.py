import argparse
import asyncio
import json
import os
import subprocess
import sys
from pathlib import Path

from rich.console import Console

from evals.cve_environments import Launch
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
from mcp_auditor.adapters.llm import create_judge_llm, create_llm
from mcp_auditor.adapters.mcp_client import StdioMCPClient
from mcp_auditor.config import load_settings
from mcp_auditor.domain.models import AttackContext, AuditReport
from mcp_auditor.graph.builder import build_graph

CVE_RUNS = 3
CVE_TEST_BUDGET = 10
DEFAULT_REPORT_PATH = "output/cve_report.json"

_EXPECTED_IMAGES = (
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
        help="No-LLM ground-truth exploit per target; confirms each fixture is live.",
    )
    parser.add_argument(
        "--cve",
        action="append",
        metavar="CVE-ID",
        help="Run only these CVE ids (repeatable); default: all.",
    )
    args = parser.parse_args()

    graded = _filter_by_cve(CVE_TARGETS, args.cve)
    tracked = _filter_by_cve(OUT_OF_SCOPE_CVES, args.cve)
    _reject_unknown_cves(args.cve, {t.cve_id for t in (*graded, *tracked)})

    if not _preflight_ok():
        sys.exit(1)

    if args.calibrate:
        sys.exit(0 if asyncio.run(calibrate_all(graded)) else 1)

    results = asyncio.run(run_cve_benchmark(graded, args.budget, args.runs))
    results.extend(out_of_scope_results(tracked))

    report_path = Path(args.report)
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
    missing = [image for image in _EXPECTED_IMAGES if not _image_exists(image)]
    if missing:
        console.print(f"[red]Missing images:[/red] {', '.join(missing)}. To build: {_BUILD_HINT}.")
        return False
    return True


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
            except (LaunchError, subprocess.CalledProcessError) as exc:
                console.print(f"[yellow]{target.cve_id} run skipped:[/yellow] {exc}")
                continue
        results.append(
            not_run(target) if not detections else resolve_status(target, detections, budget)
        )
    return results


async def calibrate_all(targets: list[CVETarget]) -> bool:
    console.print("[bold]Calibration[/bold] (no LLM): raw ground-truth exploit per target\n")
    all_live = True
    for target in targets:
        live = await _calibrate_one(target)
        all_live = all_live and live
        status = "[green]live[/green]" if live else "[red]dead[/red]"
        console.print(f"{status}  {target.cve_id}")
    if not all_live:
        console.print("\n[red]Some fixtures calibrate dead[/red]: fix fixture/exploit/tool-name.")
    return all_live


async def _calibrate_one(target: CVETarget) -> bool:
    devnull = open(os.devnull, "w")  # noqa: SIM115
    try:
        with target.environment() as launch:
            async with StdioMCPClient.connect(
                launch.command, launch.args, errlog=devnull
            ) as client:
                return await target.calibrate(client)
    except (subprocess.CalledProcessError, OSError, RuntimeError) as exc:
        console.print(f"[yellow]{target.cve_id} calibration error:[/yellow] {exc}")
        return False
    finally:
        devnull.close()


async def _audit(launch: Launch, target: CVETarget, budget: int) -> AuditReport:
    settings = load_settings()
    llm = create_llm(settings)
    judge_llm = create_judge_llm(settings)
    devnull = open(os.devnull, "w")  # noqa: SIM115
    try:
        async with StdioMCPClient.connect(
            launch.command, launch.args, errlog=devnull
        ) as mcp_client:
            graph = build_graph(
                llm, mcp_client, judge_llm=judge_llm, tools_filter=target.tools_filter
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
    finally:
        devnull.close()


if __name__ == "__main__":
    main()
