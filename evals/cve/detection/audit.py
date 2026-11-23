"""One graded audit of a target on its pinned server, for the gated session."""

import dataclasses
import subprocess
from collections import Counter
from collections.abc import Awaitable, Callable

from rich.markup import escape

from evals.cve.audit_attempts import (
    AttemptOutcome,
    IncompleteAttempt,
    ProviderErrorAttempt,
    ThrottledAttempt,
    graded_despite_missed_model_calls,
    graded_or_incomplete,
)
from evals.cve.detection.replay import ReplayOutcome, RunToCheck, replay_with_causes
from evals.cve.detection.session_model import AuditTarget, GradedAudit
from evals.cve.detection.targets import Target
from evals.cve.environments import Launch
from evals.cve.failure_text import ReportDetail
from evals.cve.grammar import DETECTION_RUNGS, CreditCheck, PlantedTarget, RunGrade, grade_run
from evals.cve.launch_audit import (
    NO_OVERRIDES,
    Auditor,
    LaunchAudit,
    RunOverrides,
    UndecidableLaunch,
    audit_launch,
    build_auditor,
    print_lost_connections,
    print_report_incidents,
)
from evals.cve.places import Places, kept_records
from evals.cve.planting import PlantingFailed
from evals.cve.provider_errors import (
    AuditFailed,
    ProviderErrorKind,
    ProviderFatal,
    describe_provider_error,
)
from evals.cve.report_units import units_of
from evals.cve.server_health import NO_INCIDENTS, ServerHealth
from evals.eval_display import console
from evals.metrics import blocked_reasons
from evals.session_usage import SessionThrottles, throttled_model_calls
from mcp_auditor.domain.models import AuditReport


class LaunchError(Exception):
    """A pinned server failed to launch or install (infra, not a detection miss)."""


def audit_target(
    test_budget: int,
    throttles: SessionThrottles,
    places: Places,
    overrides: RunOverrides = NO_OVERRIDES,
) -> AuditTarget:
    # The composition root bounds the returned audit to the chosen concurrency.
    auditor = build_auditor(test_budget)

    async def audit(target: Target) -> GradedAudit | None:
        return await graded_despite_missed_model_calls(
            target, lambda: attempt_once(target, auditor, throttles, places, overrides)
        )

    return audit


async def attempt_once(
    target: Target,
    auditor: Auditor,
    throttles: SessionThrottles,
    places: Places,
    overrides: RunOverrides = NO_OVERRIDES,
) -> AttemptOutcome[GradedAudit]:
    """Raises `ProviderFatal` on a provider error no retry cures."""
    # An unknown kept id, a planting_spec refusal or a launch whose container name cannot be read
    # is a configuration error: it is not caught here, so it crashes the run rather than reading
    # as a skip the gate cannot compare. A server taken as down reaches here as a `LaunchError`.
    records = kept_records(target.kept_places, places)
    run: RunToCheck | None = None
    health = NO_INCIDENTS
    try:
        async with target.launched(records) as planted:
            audit = await _audit(planted.launch, target, auditor, overrides)
            health = audit.health
            throttles.count(audit.report, target.flaw_id)
            _print_incidents(target, audit.report, auditor.report_detail)
            print_lost_connections(target.flaw_id, health)
            # Captured before the target's launch is left, so a raising exit of `target.launched`
            # cannot erase a completed run (the client's own teardown error is tolerated inside
            # `connect`). The nonces travel per launch, so the graded target is built here.
            run = RunToCheck(
                target=target,
                run_target=PlantedTarget(target.classes, target.aim, planted.nonces),
                report=audit.report,
                recorded_calls=audit.exchanges,
                records=records,
                relaunched_after=audit.relaunched_after,
            )
    except AuditFailed as failure:
        return _provider_error_attempt(target, failure)
    except (LaunchError, PlantingFailed, subprocess.CalledProcessError) as exc:
        failure = "run skipped" if run is None else "teardown failed"
        described = auditor.report_detail.describe(exc)
        console.print(f"[yellow]{target.flaw_id} {failure}:[/yellow] {escape(described)}")
    if run is None:
        return None
    if throttled_model_calls(run.report):
        console.print(
            f"[yellow]{target.flaw_id} run skipped:[/yellow]"
            " throttled by the model provider past every retry"
        )
        return ThrottledAttempt()
    return await _graded(run, health)


def _provider_error_attempt(target: Target, failure: AuditFailed) -> ProviderErrorAttempt:
    if failure.kind is ProviderErrorKind.FATAL:
        raise ProviderFatal(failure.cause) from failure.cause
    description = describe_provider_error(failure.cause)
    console.print(f"[yellow]{target.flaw_id} run skipped:[/yellow] provider error ({description})")
    return ProviderErrorAttempt(description)


async def _graded(run: RunToCheck, health: ServerHealth) -> GradedAudit | IncompleteAttempt:
    # The replay launches the patched version, so it runs only once the vulnerable one has exited.
    grade, replayed = await checked_grade(run)
    outcome = graded_or_incomplete(grade, run.report)
    if isinstance(outcome, IncompleteAttempt):
        return dataclasses.replace(outcome, health=health)
    console.print(f"{run.target.flaw_id}: {outcome.status}")
    return GradedAudit(
        outcome, run.report, health, replayed.unchecked_reason, replayed.attempt_failures
    )


async def checked_grade(
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
            f"[yellow]{run.target.flaw_id}: replay unchecked,"
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


def _print_incidents(target: Target, report: AuditReport, detail: ReportDetail) -> None:
    for reason in blocked_reasons(report):
        console.print(f"[yellow]{target.flaw_id}: payload blocked, {reason}[/yellow]")
    print_report_incidents(target.flaw_id, report, detail)


async def _audit(
    launch: Launch, target: Target, auditor: Auditor, overrides: RunOverrides
) -> LaunchAudit:
    try:
        return await audit_launch(launch, auditor, overrides.shape(target.tools_filter))
    except (AuditFailed, UndecidableLaunch):
        raise
    except Exception as exc:
        raise LaunchError(str(exc)) from exc
