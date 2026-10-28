"""One graded audit of a CVE target on its pinned server, for the gated session."""

import dataclasses
import os
import subprocess
from collections import Counter
from collections.abc import AsyncGenerator, Awaitable, Callable
from contextlib import asynccontextmanager
from dataclasses import dataclass

from rich.markup import escape

from evals.audit_attempts import (
    AttemptOutcome,
    IncompleteAttempt,
    ProviderErrorAttempt,
    ThrottledAttempt,
    graded_despite_missed_steps,
    graded_or_incomplete,
)
from evals.cve_environments import TOOL_CALL_TIMEOUT, Launch, connect
from evals.cve_grammar import DETECTION_RUNGS, CreditCheck, PlantedTarget, RunGrade, grade_run
from evals.cve_places import Places, kept_records
from evals.cve_planting import PlantingFailed
from evals.cve_recording_client import RecordingClient
from evals.cve_replay import RecordedCall, ReplayOutcome, RunToCheck, replay_with_causes
from evals.cve_report_units import units_of
from evals.cve_session_model import AuditTarget, GradedAudit
from evals.cve_targets import CVETarget
from evals.eval_display import console
from evals.failure_text import FULL_DETAIL, ReportDetail
from evals.metrics import SessionThrottles, blocked_reasons
from evals.provider_errors import (
    AuditFailed,
    ProviderErrorKind,
    ProviderFatal,
    audit_failures_unwrapped,
    classified,
    describe_provider_error,
)
from evals.server_health import NO_INCIDENTS, ServerHealth, health_of
from mcp_auditor.adapters.llm import create_judge_llm, create_llm
from mcp_auditor.adapters.llm_throttling import one_audit
from mcp_auditor.config import load_settings
from mcp_auditor.domain.audited_server import AuditedServer
from mcp_auditor.domain.models import AttackContext, AuditReport, MissCause
from mcp_auditor.domain.ports import LLMPort, MCPClientPort
from mcp_auditor.graph.builder import build_graph


class LaunchError(Exception):
    """A pinned server failed to launch or install (infra, not a detection miss)."""


@dataclass(frozen=True)
class Auditor:
    llm: LLMPort
    judge_llm: LLMPort
    budget: int
    report_detail: ReportDetail = FULL_DETAIL


@dataclass(frozen=True)
class RunOverrides:
    """Uniform run conditions applied to every target, each setting left None keeping the
    launch's own."""

    chain_budget: int | None
    max_chain_steps: int | None
    tool_call_timeout: int | None
    audit_every_tool: bool = False


def build_auditor(budget: int) -> Auditor:
    # Built before any container: a bad model configuration is a crash, never a run skipped,
    # which would read as a gate that cannot compare.
    settings = load_settings()
    return Auditor(create_llm(settings), create_judge_llm(settings), budget)


def audit_target(
    budget: int,
    throttles: SessionThrottles,
    places: Places,
    overrides: RunOverrides | None = None,
) -> AuditTarget:
    # The composition root bounds the returned audit to the chosen concurrency.
    auditor = build_auditor(budget)

    async def audit(target: CVETarget) -> GradedAudit | None:
        return await graded_despite_missed_steps(
            target, lambda: attempt_once(target, auditor, throttles, places, overrides)
        )

    return audit


async def attempt_once(
    target: CVETarget,
    auditor: Auditor,
    throttles: SessionThrottles,
    places: Places,
    overrides: RunOverrides | None = None,
) -> AttemptOutcome[GradedAudit]:
    """Raises `ProviderFatal` on a provider error no retry cures."""
    # An unknown kept id or a planting_spec refusal is a configuration error: it is not
    # caught here, so it crashes the run rather than reading as a skip the gate cannot compare.
    records = kept_records(target.kept_places, places)
    run: RunToCheck | None = None
    health = NO_INCIDENTS
    try:
        async with target.launched(records) as planted:
            report, calls, health = await _audit(planted.launch, target, auditor, overrides)
            throttles.count(report, target.cve_id)
            _print_incidents(target, report, auditor.report_detail)
            _print_lost_connections(target, health)
            # Captured before the target's launch is left, so a raising exit of `target.launched`
            # cannot erase a completed run (the client's own teardown error is tolerated inside
            # `connect`). The nonces travel per launch, so the graded target is built here.
            run = RunToCheck(
                target=target,
                run_target=PlantedTarget(target.mechanism, target.aim, planted.nonces),
                report=report,
                recorded_calls=calls,
                records=records,
            )
    except AuditFailed as failure:
        return _provider_error_attempt(target, failure)
    except (LaunchError, PlantingFailed, subprocess.CalledProcessError) as exc:
        failure = "run skipped" if run is None else "teardown failed"
        described = auditor.report_detail.describe(exc)
        console.print(f"[yellow]{target.cve_id} {failure}:[/yellow] {escape(described)}")
    if run is None:
        return None
    if any(missed.cause is MissCause.PROVIDER_THROTTLED for missed in run.report.missed_steps):
        console.print(
            f"[yellow]{target.cve_id} run skipped:[/yellow]"
            " throttled by the model provider past every retry"
        )
        return ThrottledAttempt()
    return await _graded(run, health)


def _provider_error_attempt(target: CVETarget, failure: AuditFailed) -> ProviderErrorAttempt:
    if failure.kind is ProviderErrorKind.FATAL:
        raise ProviderFatal(failure.cause) from failure.cause
    description = describe_provider_error(failure.cause)
    console.print(f"[yellow]{target.cve_id} run skipped:[/yellow] provider error ({description})")
    return ProviderErrorAttempt(description)


async def _graded(run: RunToCheck, health: ServerHealth) -> GradedAudit | IncompleteAttempt:
    # The replay launches the patched version, so it runs only once the vulnerable one has exited.
    grade, replayed = await _checked_grade(run)
    outcome = graded_or_incomplete(grade, run.report)
    if isinstance(outcome, IncompleteAttempt):
        return dataclasses.replace(outcome, health=health)
    console.print(f"{run.target.cve_id}: {outcome.status}")
    return GradedAudit(
        outcome, run.report, health, replayed.unchecked_reason, replayed.attempt_failures
    )


async def _checked_grade(
    run: RunToCheck,
    *,
    replay: Callable[[RunToCheck], Awaitable[ReplayOutcome]] = replay_with_causes,
) -> tuple[RunGrade, ReplayOutcome]:
    """The run's final grade: a detecting run is replayed against the patched version and graded
    on the credits that survive the strike. A run that did not detect needs no check, since the
    strike only removes a detection."""
    units = units_of(run.report)
    grade = grade_run(run.run_target, units)
    if grade.status not in DETECTION_RUNGS:
        return grade, _NOT_REPLAYED
    replayed = await replay(run)
    if replayed.unchecked_reason is not None:
        console.print(
            f"[yellow]{run.target.cve_id}: replay unchecked,"
            f" {_describe_unchecked_replay(replayed)}[/yellow]"
        )
    return grade_run(run.run_target, units, replayed.check), replayed


_NOT_REPLAYED = ReplayOutcome(CreditCheck(frozenset(), unchecked=False), None, ())


def _describe_unchecked_replay(replayed: ReplayOutcome) -> str:
    counts = Counter(replayed.attempt_failures)
    if not counts:
        return str(replayed.unchecked_reason)
    by_cause = ", ".join(f"{cause} x{count}" for cause, count in sorted(counts.items()))
    return f"{replayed.unchecked_reason} ({by_cause})"


def _print_lost_connections(target: CVETarget, health: ServerHealth) -> None:
    if health.lost_connection_responses > 0:
        console.print(
            f"[yellow]{target.cve_id}: server connection lost on"
            f" {health.lost_connection_responses} call(s)[/yellow]"
        )


def _print_incidents(target: CVETarget, report: AuditReport, detail: ReportDetail) -> None:
    for reason in blocked_reasons(report):
        console.print(f"[yellow]{target.cve_id}: payload blocked, {reason}[/yellow]")
    for missed in report.missed_steps:
        console.print(f"[yellow]{target.cve_id}: {escape(detail.missed_detail(missed))}[/yellow]")
    throttled = report.provider_usage.throttled_requests
    if throttled > 0:
        console.print(
            f"[yellow]{target.cve_id}: throttled {throttled} time(s)"
            " by the model provider (HTTP 429)[/yellow]"
        )


async def _audit(
    launch: Launch, target: CVETarget, auditor: Auditor, overrides: RunOverrides | None
) -> tuple[AuditReport, list[RecordedCall], ServerHealth]:
    forced = overrides or RunOverrides(None, None, None)
    chain_budget = _either(forced.chain_budget, launch.chain_budget)
    max_chain_steps = _either(forced.max_chain_steps, launch.max_chain_steps)
    try:
        with audit_failures_unwrapped():
            async with _silent_client(launch, overrides) as mcp_client:
                recorder = RecordingClient(mcp_client)
                graph = build_graph(
                    auditor.llm,
                    AuditedServer(recorder),
                    judge_llm=auditor.judge_llm,
                    tools_filter=None if forced.audit_every_tool else target.tools_filter,
                )
                with one_audit():
                    result = await classified(
                        graph.ainvoke(  # pyright: ignore[reportUnknownMemberType, reportUnknownArgumentType]
                            {
                                "target": f"{launch.command} {' '.join(launch.args)}",
                                "test_budget": auditor.budget,
                                "attack_context": AttackContext(),
                                "chain_budget": chain_budget,
                                "max_chain_steps": max_chain_steps,
                            }
                        )
                    )
                health = health_of(mcp_client, recorder.exchanges)
                return result["audit_report"], recorder.exchanges, health
    except AuditFailed:
        raise
    except Exception as exc:
        raise LaunchError(str(exc)) from exc


@asynccontextmanager
async def _silent_client(
    launch: Launch, overrides: RunOverrides | None
) -> AsyncGenerator[MCPClientPort]:
    timeout = _either(None if overrides is None else overrides.tool_call_timeout, TOOL_CALL_TIMEOUT)
    with open(os.devnull, "w") as devnull:
        async with connect(launch, devnull, tool_call_timeout=timeout) as client:
            yield client


def _either(forced: int | None, own: int) -> int:
    return own if forced is None else forced
