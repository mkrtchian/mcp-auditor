"""One graded audit of a CVE target on its pinned server, for the gated session."""

import os
import subprocess
from collections.abc import AsyncGenerator, Awaitable, Callable
from contextlib import asynccontextmanager
from dataclasses import dataclass

from rich.console import Console
from rich.markup import escape

from evals.cve_environments import TOOL_CALL_TIMEOUT, Launch, connect
from evals.cve_grammar import DETECTION_RUNGS, CreditCheck, PlantedTarget, RunGrade, grade_run
from evals.cve_places import Places, kept_records
from evals.cve_planting import PlantingFailed
from evals.cve_recording_client import RecordingClient
from evals.cve_replay import RecordedCall, RunToCheck, replay_credit
from evals.cve_report_units import units_of
from evals.cve_session_model import AuditTarget, GradedAudit
from evals.cve_targets import CVETarget
from evals.metrics import SessionThrottles, blocked_reasons, missed_steps
from mcp_auditor.adapters.llm import create_judge_llm, create_llm
from mcp_auditor.config import load_settings
from mcp_auditor.domain.audited_server import AuditedServer
from mcp_auditor.domain.models import AttackContext, AuditReport, MissCause
from mcp_auditor.domain.ports import LLMPort, MCPClientPort
from mcp_auditor.graph.builder import build_graph

console = Console()

# A policy refusal stops a step, so the run says nothing of detection. The generated prompts
# differ from one audit to the next, so a new attempt usually passes the provider's filter.
INCOMPLETE_ATTEMPTS = 3


class LaunchError(Exception):
    """A pinned server failed to launch or install (infra, not a detection miss)."""


@dataclass(frozen=True)
class Auditor:
    llm: LLMPort
    judge_llm: LLMPort
    budget: int


@dataclass(frozen=True)
class RunOverrides:
    """Uniform run conditions the holdout applies to every target in place of the launch's own."""

    chain_budget: int
    max_chain_steps: int
    tool_call_timeout: int


def build_auditor(budget: int) -> Auditor:
    # Built before any container: a bad model configuration is a crash, never a run skipped,
    # which would read as a gate that cannot compare.
    settings = load_settings()
    return Auditor(create_llm(settings), create_judge_llm(settings), budget)


def audit_target(budget: int, throttles: SessionThrottles, places: Places) -> AuditTarget:
    # The composition root bounds the returned audit to the chosen concurrency.
    auditor = build_auditor(budget)

    async def audit(target: CVETarget) -> GradedAudit | None:
        return await graded_despite_refusals(
            target, lambda: attempt_once(target, auditor, throttles, places)
        )

    return audit


@dataclass(frozen=True)
class IncompleteAttempt:
    """An audit that did not detect and whose report holds a missed step, with its causes."""

    report: AuditReport
    causes: frozenset[MissCause]


_CAUSE_WORDING = {
    MissCause.PROVIDER_REFUSAL: "refused by the model provider",
    MissCause.UNREADABLE_ANSWER: "unreadable model answer",
}


def describe_miss_causes(causes: frozenset[MissCause]) -> str:
    return " and ".join(wording for cause, wording in _CAUSE_WORDING.items() if cause in causes)


async def graded_despite_refusals[T](
    target: CVETarget, attempt: Callable[[], Awaitable[T | IncompleteAttempt | None]]
) -> T | None:
    """The first complete attempt grades the run. None when every attempt missed a step."""
    causes: frozenset[MissCause] = frozenset()
    for number in range(1, INCOMPLETE_ATTEMPTS + 1):
        outcome = await attempt()
        if not isinstance(outcome, IncompleteAttempt):
            return outcome
        causes |= outcome.causes
        console.print(
            f"[yellow]{target.cve_id}: attempt {number}/{INCOMPLETE_ATTEMPTS}:"
            f" {describe_miss_causes(outcome.causes)}, not graded[/yellow]"
        )
    console.print(
        f"[yellow]{target.cve_id} run skipped:[/yellow] a step missed at all"
        f" {INCOMPLETE_ATTEMPTS} attempts ({describe_miss_causes(causes)})"
    )
    return None


async def attempt_once(
    target: CVETarget,
    auditor: Auditor,
    throttles: SessionThrottles,
    places: Places,
    overrides: RunOverrides | None = None,
) -> GradedAudit | IncompleteAttempt | None:
    # An unknown kept id or a planting_spec refusal is a configuration error: it is not
    # caught here, so it crashes the run rather than reading as a skip the gate cannot compare.
    records = kept_records(target.kept_places, places)
    run: RunToCheck | None = None
    try:
        async with target.launched(records) as planted:
            report, calls = await _audit(planted.launch, target, auditor, overrides)
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
    outcome = graded_or_incomplete(grade, run.report)
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


def graded_or_incomplete(grade: RunGrade, report: AuditReport) -> RunGrade | IncompleteAttempt:
    """A detection carries its own proof and stands whatever step was refused. A run that did
    not detect with a refused step says nothing of detection, the struck credit included."""
    if report.missed_steps and grade.status not in DETECTION_RUNGS:
        return IncompleteAttempt(report, frozenset(missed.cause for missed in report.missed_steps))
    return grade


def _print_incidents(target: CVETarget, report: AuditReport) -> None:
    for reason in blocked_reasons(report):
        console.print(f"[yellow]{target.cve_id}: payload blocked, {reason}[/yellow]")
    for missed in missed_steps(report):
        console.print(f"[yellow]{target.cve_id}: {escape(missed)}[/yellow]")
    throttled = report.provider_usage.throttled_requests
    if throttled > 0:
        console.print(
            f"[yellow]{target.cve_id}: throttled {throttled} time(s)"
            " by the model provider (HTTP 429)[/yellow]"
        )


async def _audit(
    launch: Launch, target: CVETarget, auditor: Auditor, overrides: RunOverrides | None
) -> tuple[AuditReport, list[RecordedCall]]:
    chain_budget = launch.chain_budget if overrides is None else overrides.chain_budget
    max_chain_steps = launch.max_chain_steps if overrides is None else overrides.max_chain_steps
    try:
        async with _silent_client(launch, overrides) as mcp_client:
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
                    "chain_budget": chain_budget,
                    "max_chain_steps": max_chain_steps,
                }
            )
            return result["audit_report"], recorder.exchanges
    except Exception as exc:
        raise LaunchError(str(exc)) from exc


@asynccontextmanager
async def _silent_client(
    launch: Launch, overrides: RunOverrides | None
) -> AsyncGenerator[MCPClientPort]:
    timeout = TOOL_CALL_TIMEOUT if overrides is None else overrides.tool_call_timeout
    with open(os.devnull, "w") as devnull:
        async with connect(launch, devnull, tool_call_timeout=timeout) as client:
            yield client
