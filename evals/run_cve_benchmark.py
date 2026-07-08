import argparse
import asyncio
import json
import os
import tempfile
from pathlib import Path

from rich.console import Console

from evals.cve_oracle import (
    CVEResult,
    RunDetection,
    detect_in_report,
    not_run,
    out_of_scope_results,
    render_markdown,
    resolve_status,
)
from evals.cve_targets import CVE_TARGETS, OUT_OF_SCOPE_CVES, CVETarget, Launch
from mcp_auditor.adapters.llm import create_judge_llm, create_llm
from mcp_auditor.adapters.mcp_client import StdioMCPClient
from mcp_auditor.config import load_settings
from mcp_auditor.domain.models import AttackContext, AuditReport
from mcp_auditor.graph.builder import build_graph

CVE_RUNS = 3
CVE_TEST_BUDGET = 10
DEFAULT_REPORT_PATH = "output/cve_report.json"

console = Console()


class LaunchError(Exception):
    """A pinned server failed to launch or install (infra, not a detection miss)."""


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the CVE validation benchmark")
    parser.add_argument("--runs", type=int, default=CVE_RUNS)
    parser.add_argument("--budget", type=int, default=CVE_TEST_BUDGET)
    parser.add_argument("--report", type=str, default=DEFAULT_REPORT_PATH)
    args = parser.parse_args()

    results = asyncio.run(run_cve_benchmark(args.budget, args.runs))
    results.extend(out_of_scope_results(OUT_OF_SCOPE_CVES))

    report_path = Path(args.report)
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(json.dumps([r.model_dump(mode="json") for r in results], indent=2))
    markdown = render_markdown(results)
    report_path.with_suffix(".md").write_text(markdown)

    console.print(markdown)
    console.print(f"Report written to {report_path}")


async def run_cve_benchmark(budget: int, runs: int) -> list[CVEResult]:
    results: list[CVEResult] = []
    for target in CVE_TARGETS:
        detections: list[RunDetection] = []
        for _ in range(runs):
            with tempfile.TemporaryDirectory() as tmp:
                try:
                    launch = target.prepare(Path(tmp))
                    report = await _audit(launch, target, budget)
                except LaunchError as exc:
                    console.print(f"[yellow]{target.cve_id} run skipped:[/yellow] {exc}")
                    continue
                detections.append(detect_in_report(target, report))
        results.append(
            not_run(target) if not detections else resolve_status(target, detections, budget)
        )
    return results


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
