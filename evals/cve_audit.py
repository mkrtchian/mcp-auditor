"""One graded audit of a CVE target on its pinned server, for the gated session."""

import os
import subprocess
from collections.abc import AsyncGenerator, Awaitable, Callable
from contextlib import asynccontextmanager
from dataclasses import dataclass

from rich.console import Console
from rich.markup import escape

from evals.cve_environments import Launch, connect
from evals.cve_grammar import DETECTION_RUNGS, CreditCheck, PlantedTarget, RunGrade, grade_run
from evals.cve_places import Places, kept_records
from evals.cve_planting import PlantingFailed
from evals.cve_recording_client import RecordingClient
from evals.cve_replay import RecordedCall, RunToCheck, replay_credit
from evals.cve_report_units import units_of
from evals.cve_session_model import AuditTarget, GradedAudit
from evals.cve_targets import CVETarget
from evals.metrics import SessionThrottles, blocked_reasons, refused_steps
from mcp_auditor.adapters.llm import create_judge_llm, create_llm
from mcp_auditor.config import load_settings
from mcp_auditor.domain.audited_server import AuditedServer
from mcp_auditor.domain.models import AttackContext, AuditReport
from mcp_auditor.domain.ports import LLMPort, MCPClientPort
from mcp_auditor.graph.builder import build_graph

console = Console()

# A policy refusal stops a step, so the run says nothing of detection. The generated prompts
# differ from one audit to the next, so a new attempt usually passes the provider's filter.
REFUSAL_ATTEMPTS = 3


class LaunchError(Exception):
    """A pinned server failed to launch or install (infra, not a detection miss)."""


@dataclass(frozen=True)
class _Auditor:
    llm: LLMPort
    judge_llm: LLMPort
    budget: int


def audit_target(budget: int, throttles: SessionThrottles, places: Places) -> AuditTarget:
    # Built once, before any container: a bad model configuration is a crash, never a
    # run skipped, which would read as a gate that cannot compare. The composition root
    # bounds the returned audit to the chosen concurrency.
    settings = load_settings()
    auditor = _Auditor(create_llm(settings), create_judge_llm(settings), budget)

    async def audit(target: CVETarget) -> GradedAudit | None:
        return await graded_despite_refusals(
            target, lambda: _attempt(target, auditor, throttles, places)
        )

    return audit


@dataclass(frozen=True)
class RefusedAttempt:
    """An audit whose report holds a step the model provider refused."""


async def graded_despite_refusals[T](
    target: CVETarget, attempt: Callable[[], Awaitable[T | RefusedAttempt | None]]
) -> T | None:
    """The first attempt not refused grades the run. None when every attempt is refused."""
    for number in range(1, REFUSAL_ATTEMPTS + 1):
        outcome = await attempt()
        if not isinstance(outcome, RefusedAttempt):
            return outcome
        console.print(
            f"[yellow]{target.cve_id}: attempt {number}/{REFUSAL_ATTEMPTS} refused by the"
            " model provider, not graded[/yellow]"
        )
    console.print(
        f"[yellow]{target.cve_id} run skipped:[/yellow] refused by the model provider"
        f" at all {REFUSAL_ATTEMPTS} attempts"
    )
    return None


async def _attempt(
    target: CVETarget, auditor: _Auditor, throttles: SessionThrottles, places: Places
) -> GradedAudit | RefusedAttempt | None:
    # An unknown kept id or a planting_spec refusal is a configuration error: it is not
    # caught here, so it crashes the run rather than reading as a skip the gate cannot compare.
    records = kept_records(target.kept_places, places)
    run: RunToCheck | None = None
    try:
        async with target.launched(records) as planted:
            report, calls = await _audit(planted.launch, target, auditor)
            throttles.count(report)
            _print_incidents(target, report)
            # Captured before __exit__ fires, so a best-effort teardown error cannot erase a
            # completed run. The nonces travel per launch, so the graded target is built here.
            run = RunToCheck(
                target=target,
                run_target=PlantedTarget(target.mechanism, target.aim, planted.nonces),
                report=report,
                recorded_calls=calls,
                records=records,
            )
    except (LaunchError, PlantingFailed, subprocess.CalledProcessError) as exc:
        failure = "run skipped" if run is None else "teardown failed"
        console.print(f"[yellow]{target.cve_id} {failure}:[/yellow] {exc}")
    if run is None:
        return None
    # The replay launches the patched version, so it runs only once the vulnerable one has exited.
    grade = await _checked_grade(run)
    outcome = graded_or_refused(grade, run.report)
    if isinstance(outcome, RunGrade):
        console.print(f"{target.cve_id}: {outcome.status}")
        return GradedAudit(outcome, run.report)
    return outcome


async def _checked_grade(
    run: RunToCheck,
    *,
    replay: Callable[[RunToCheck], Awaitable[CreditCheck]] = replay_credit,
) -> RunGrade:
    """The run's final grade: a detecting run is replayed against the patched version and graded
    on the credits that survive the strike. A run that did not detect needs no check, since the
    strike only removes a detection."""
    units = units_of(run.report)
    grade = grade_run(run.run_target, units)
    if grade.status not in DETECTION_RUNGS:
        return grade
    check = await replay(run)
    return grade_run(run.run_target, units, check)


def graded_or_refused(grade: RunGrade, report: AuditReport) -> RunGrade | RefusedAttempt:
    """A detection carries its own proof and stands whatever step was refused. A run that did
    not detect with a refused step says nothing of detection, the struck credit included."""
    if report.refused_steps and grade.status not in DETECTION_RUNGS:
        return RefusedAttempt()
    return grade


def _print_incidents(target: CVETarget, report: AuditReport) -> None:
    for reason in blocked_reasons(report):
        console.print(f"[yellow]{target.cve_id}: payload blocked, {reason}[/yellow]")
    for refused in refused_steps(report):
        console.print(
            f"[yellow]{target.cve_id}: refused by the model provider, {escape(refused)}[/yellow]"
        )
    throttled = report.provider_usage.throttled_requests
    if throttled > 0:
        console.print(
            f"[yellow]{target.cve_id}: throttled {throttled} time(s)"
            " by the model provider (HTTP 429)[/yellow]"
        )


async def _audit(
    launch: Launch, target: CVETarget, auditor: _Auditor
) -> tuple[AuditReport, list[RecordedCall]]:
    try:
        async with _silent_client(launch) as mcp_client:
            recorder = RecordingClient(mcp_client)
            graph = build_graph(
                auditor.llm,
                AuditedServer(recorder),
                judge_llm=auditor.judge_llm,
                tools_filter=target.tools_filter,
            )
            result = await graph.ainvoke(  # pyright: ignore[reportUnknownMemberType]
                {
                    "target": f"{launch.command} {' '.join(launch.args)}",
                    "test_budget": auditor.budget,
                    "attack_context": AttackContext(),
                    "chain_budget": launch.chain_budget,
                    "max_chain_steps": launch.max_chain_steps,
                }
            )
            return result["audit_report"], recorder.exchanges
    except Exception as exc:
        raise LaunchError(str(exc)) from exc


@asynccontextmanager
async def _silent_client(launch: Launch) -> AsyncGenerator[MCPClientPort]:
    with open(os.devnull, "w") as devnull:
        async with connect(launch, devnull) as client:
            yield client
