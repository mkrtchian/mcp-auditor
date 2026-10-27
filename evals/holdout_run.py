"""The holdout run orchestrator: audit every drawn target at one commit under the rule's run
conditions, keep no per-case trace, and assemble the per-target and whole-run results.

A sibling of the acceptance gated session (`cve_session`): no gate, no baseline, no judged-case
export, the opposite missed-step policy (`holdout_audit`). The targets are passed in, never read
from `HOLDOUT_TARGETS` here, so the tests hand it crafted ones. The heavy I/O is grouped in
`HoldoutDeps`, faked by the unit tests and built from the live settings by `default_deps`.
"""

import asyncio
import subprocess
from collections.abc import Awaitable, Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import date

from evals.concurrency import bounded
from evals.cve_audit import RunOverrides, attempt_once, build_auditor
from evals.cve_baseline import (
    backend_image_ids,
    fixture_fingerprint,
    grammar_fingerprint,
    image_ids,
)
from evals.cve_calibration import check_target
from evals.cve_grammar import DETECTION_RUNGS, RunGrade
from evals.cve_images import COMPOSE_FILE
from evals.cve_layout_check import LayoutCheck, layout_check, observe_versions
from evals.cve_places import Places, kept_records
from evals.cve_session_model import GradedAudit
from evals.cve_targets import CVETarget, LaunchMode
from evals.eval_runs import tracing_enabled
from evals.eval_session import Refused, TreeState, read_tree
from evals.holdout_audit import DroppedRun, IncompleteRun, holdout_audit
from evals.holdout_conditions import HoldoutConditions
from evals.holdout_results import (
    DROPPED_RUN_REASONS,
    HoldoutRunResult,
    HoldoutRunStatus,
    HoldoutTargetResult,
    NotRunCause,
    NotRunTarget,
)
from evals.metrics import SessionThrottles
from evals.probe import call_cost
from evals.probe_candidates import Prices
from mcp_auditor.config import Settings
from mcp_auditor.domain.models import AuditReport

HOLDOUT_RUNS = 3  # holdout-rule.md:235, lowerable to 1 and logged
HOLDOUT_BUDGET = 10  # holdout-rule.md:227, a constant, not a flag
HOLDOUT_CONCURRENCY = 6

type Audit = Callable[[CVETarget], Awaitable[GradedAudit | IncompleteRun | DroppedRun]]


@dataclass(frozen=True)
class HoldoutDeps:
    audit: Audit
    check: Callable[[CVETarget], Awaitable[list[str]]]  # the dead conditions on both versions
    layout: Callable[[CVETarget], Awaitable[LayoutCheck]]
    rebuild: Callable[[Sequence[str]], None]
    image_ids: Callable[[Sequence[str]], dict[str, str]]
    backend_image_ids: Callable[[Sequence[str]], dict[str, str]]
    read_tree: Callable[[], TreeState]


@dataclass(frozen=True)
class _RunContext:
    conditions: HoldoutConditions
    settings: Settings
    places: Places
    disclosure_dates: Mapping[str, date]
    model_ids: list[str]
    runs: int
    census_commit: str


async def run_holdout(
    targets: Sequence[CVETarget],
    disclosure_dates: Mapping[str, date],
    conditions: HoldoutConditions,
    settings: Settings,
    places: Places,
    census_commit: str,
    *,
    runs: int = HOLDOUT_RUNS,
    concurrency: int = HOLDOUT_CONCURRENCY,
    deps: HoldoutDeps | None = None,
) -> HoldoutRunResult:
    _refuse_tracing()
    _refuse_tools_filter(targets)
    _refuse_missing_census(targets, disclosure_dates)
    _refuse_unknown_places(targets, places)
    model_ids = list(dict.fromkeys([settings.resolve_model(), settings.resolve_judge_model()]))
    ctx = _RunContext(
        conditions, settings, places, disclosure_dates, model_ids, runs, census_commit
    )
    conditions.require_ready(model_ids)
    deps = deps or default_deps(places, _overrides(conditions), concurrency)
    tree = deps.read_tree()
    _refuse_dirty_tree(tree)
    deps.rebuild(target_services(list(targets)))
    not_run, surviving = await _vet_all(targets, deps)
    assembled, dropped = await _run_all(surviving, deps, ctx)
    all_not_run = [*not_run, *dropped]
    if not assembled:
        raise Refused(
            "holdout run refused",
            ["no target survived the pre-run check", *(entry.reason for entry in all_not_run)],
        )
    return _assemble_run(ctx, deps, assembled, all_not_run, tree)


def _refuse_tracing() -> None:
    if tracing_enabled():
        raise Refused(
            "holdout run refused",
            ["LANGSMITH_TRACING or LANGCHAIN_TRACING_V2 is set; a holdout run keeps no trace"],
        )


def _refuse_tools_filter(targets: Sequence[CVETarget]) -> None:
    filtered = [target.cve_id for target in targets if target.tools_filter is not None]
    if filtered:
        raise Refused(
            "holdout run refused",
            [f"the rule runs with no tools filter, but {name} carries one" for name in filtered],
        )


def _refuse_missing_census(
    targets: Sequence[CVETarget], disclosure_dates: Mapping[str, date]
) -> None:
    missing = [target.cve_id for target in targets if target.cve_id not in disclosure_dates]
    if missing:
        raise Refused(
            "holdout run refused",
            [f"{name} is drawn but absent from the census" for name in missing],
        )


def _refuse_unknown_places(targets: Sequence[CVETarget], places: Places) -> None:
    reasons: list[str] = []
    for target in targets:
        try:
            target.planting_spec(kept_records(target.kept_places, places))
        except ValueError as exc:
            reasons.append(f"{target.cve_id}: {exc}")
    if reasons:
        raise Refused("holdout run refused", reasons)


def _refuse_dirty_tree(tree: TreeState) -> None:
    if tree.dirty:
        raise Refused(
            "holdout run refused",
            ["the git tree is dirty: a holdout run publishes from a clean tree"],
        )


def _overrides(conditions: HoldoutConditions) -> RunOverrides:
    chain, steps = conditions.chain_budget, conditions.max_chain_steps
    timeout = conditions.tool_call_timeout
    assert chain is not None and steps is not None and timeout is not None  # require_ready passed
    return RunOverrides(chain, steps, timeout)


def default_deps(places: Places, overrides: RunOverrides, concurrency: int) -> HoldoutDeps:
    auditor = build_auditor(HOLDOUT_BUDGET)
    throttles = SessionThrottles()

    async def audit(target: CVETarget) -> GradedAudit | IncompleteRun | DroppedRun:
        return await holdout_audit(
            target, lambda: attempt_once(target, auditor, throttles, places, overrides)
        )

    async def check(target: CVETarget) -> list[str]:
        return await check_target(target, places)

    async def layout(target: CVETarget) -> LayoutCheck:
        return await _observe_layout(target, places)

    return HoldoutDeps(
        bounded(audit, concurrency),
        bounded(check, concurrency),
        bounded(layout, concurrency),
        rebuild_images,
        image_ids,
        backend_image_ids,
        read_tree,
    )


async def _observe_layout(target: CVETarget, places: Places) -> LayoutCheck:
    vuln, patched = await observe_versions(target, places)
    return layout_check(target, kept_records(target.kept_places, places), vuln, patched)


async def _vet_all(
    targets: Sequence[CVETarget], deps: HoldoutDeps
) -> tuple[list[NotRunTarget], list[CVETarget]]:
    reasons = await asyncio.gather(*(_vet(target, deps) for target in targets))
    paired = list(zip(targets, reasons, strict=True))
    not_run = [
        NotRunTarget(t.cve_id, r, NotRunCause.PRE_RUN_CHECK) for t, r in paired if r is not None
    ]
    surviving = [t for t, r in paired if r is None]
    return not_run, surviving


async def _vet(target: CVETarget, deps: HoldoutDeps) -> str | None:
    conditions = await deps.check(target)
    layout = await deps.layout(target)
    return vet_reason(target, conditions, layout)


def vet_reason(target: CVETarget, conditions: list[str], layout: LayoutCheck) -> str | None:
    """Why a target is dropped from N before any audit, or None to run it. A break keeps a FALLBACK
    target but drops a NORMAL one calibrated under a launch it lost (holdout-rule.md:159)."""
    if conditions:
        return "dead on a version: " + "; ".join(conditions)
    if layout.gave_up is not None:
        return layout.gave_up
    if layout.breaks and target.launch_mode is LaunchMode.NORMAL:
        return "the layout breaks the server under the normal launch"
    if layout.unrouted:
        return "kept layout place(s) without a route: " + ", ".join(layout.unrouted)
    return None


async def _run_all(
    surviving: Sequence[CVETarget], deps: HoldoutDeps, ctx: _RunContext
) -> tuple[list[tuple[CVETarget, HoldoutTargetResult]], list[NotRunTarget]]:
    runs_per = await asyncio.gather(
        *(_run_target(target, deps.audit, ctx.runs) for target in surviving)
    )
    assembled: list[tuple[CVETarget, HoldoutTargetResult]] = []
    dropped: list[NotRunTarget] = []
    for target, outcomes in zip(surviving, runs_per, strict=True):
        if isinstance(outcomes, DroppedRun):
            reason = DROPPED_RUN_REASONS[outcomes.cause]
            dropped.append(NotRunTarget(target.cve_id, reason, outcomes.cause))
        else:
            assembled.append((target, _assemble_target(target, outcomes, ctx)))
    return assembled, dropped


async def _run_target(
    target: CVETarget, audit: Audit, runs: int
) -> list[GradedAudit | IncompleteRun] | DroppedRun:
    outcomes = await asyncio.gather(*(audit(target) for _ in range(runs)))
    causes = {outcome.cause for outcome in outcomes if isinstance(outcome, DroppedRun)}
    if NotRunCause.THROTTLED in causes:
        return DroppedRun(NotRunCause.THROTTLED)
    if causes:
        return DroppedRun(NotRunCause.LAUNCH_FAILURE)
    return [outcome for outcome in outcomes if not isinstance(outcome, DroppedRun)]


def _assemble_target(
    target: CVETarget, outcomes: Sequence[GradedAudit | IncompleteRun], ctx: _RunContext
) -> HoldoutTargetResult:
    grades = [outcome.grade if isinstance(outcome, GradedAudit) else None for outcome in outcomes]
    reports = [outcome.report for outcome in outcomes]
    gen_price, judge_price = _prices(ctx)
    return HoldoutTargetResult(
        cve_id=target.cve_id,
        disclosure_date=ctx.disclosure_dates[target.cve_id],
        mechanism_label=None if target.mechanism is None else target.mechanism.value,
        tools_count=len(reports[0].tool_reports),
        ran_in_fallback=target.launch_mode is LaunchMode.FALLBACK,
        statuses=tuple(_run_status(grade) for grade in grades),
        run_cost=sum(_run_cost(report, gen_price, judge_price) for report in reports),
    )


def _run_status(grade: RunGrade | None) -> HoldoutRunStatus:
    if grade is None:
        return HoldoutRunStatus(
            detected=False,
            detected_if_unchecked_missed=False,
            surfaced_places=[],
            struck_places=[],
            unchecked_places=[],
            aimed=False,
            fail_without_proof=False,
            incomplete=True,
        )
    return HoldoutRunStatus(
        detected=_detected(grade),
        detected_if_unchecked_missed=_detected_if_unchecked_missed(grade),
        surfaced_places=sorted(grade.surfaced_places),
        struck_places=sorted(grade.struck_places),
        unchecked_places=sorted(grade.unchecked_places),
        aimed=grade.aimed,
        fail_without_proof=grade.fail_without_proof,
        incomplete=False,
    )


def _detected(grade: RunGrade | None) -> bool:
    return grade is not None and grade.status in DETECTION_RUNGS


def _detected_if_unchecked_missed(grade: RunGrade | None) -> bool:
    if grade is None:
        return False
    return (grade.status_if_unchecked_missed or grade.status) in DETECTION_RUNGS


def _prices(ctx: _RunContext) -> tuple[Prices, Prices]:
    prices = ctx.conditions.prices
    return prices[ctx.settings.resolve_model()], prices[ctx.settings.resolve_judge_model()]


def _run_cost(report: AuditReport, gen_price: Prices, judge_price: Prices) -> float:
    return call_cost(report.generator_usage, gen_price) + call_cost(report.judge_usage, judge_price)


def _assemble_run(
    ctx: _RunContext,
    deps: HoldoutDeps,
    assembled: Sequence[tuple[CVETarget, HoldoutTargetResult]],
    not_run: list[NotRunTarget],
    tree: TreeState,
) -> HoldoutRunResult:
    settings = ctx.settings
    model, judge_model = settings.resolve_model(), settings.resolve_judge_model()
    targets = [target for target, _ in assembled]
    results = [result for _, result in assembled]
    return HoldoutRunResult(
        runs=ctx.runs,
        budget=HOLDOUT_BUDGET,
        provider=settings.provider,
        model=model,
        judge_model=judge_model,
        reasoning=settings.resolve_reasoning(model),
        judge_reasoning=settings.resolve_reasoning(judge_model),
        cutoffs={model_id: ctx.conditions.cutoffs[model_id] for model_id in ctx.model_ids},
        chain_budget=ctx.conditions.chain_budget,
        max_chain_steps=ctx.conditions.max_chain_steps,
        tool_call_timeout=ctx.conditions.tool_call_timeout,
        grammar_fingerprint=grammar_fingerprint(),
        fixture_fingerprints={t.cve_id: fixture_fingerprint(t, ctx.places) for t in targets},
        commit=tree.commit,
        census_commit=ctx.census_commit,
        image_ids={
            **deps.image_ids(target_services(targets)),
            **deps.backend_image_ids(_backend_images(targets)),
        },
        targets=results,
        not_run=not_run,
        incomplete_run_count=sum(result.incomplete_runs for result in results),
        total_cost=sum(result.run_cost for result in results),
        prices_as_of=ctx.conditions.prices_as_of,
    )


def rebuild_images(services: Sequence[str]) -> None:
    if not services:
        return
    build = subprocess.run(
        ["docker", "compose", "-f", str(COMPOSE_FILE), "build", *services],
        capture_output=True,
        text=True,
    )
    if build.returncode != 0:
        raise RuntimeError(
            f"docker compose build failed for {', '.join(services)}:\n"
            f"{_tail(build.stdout)}\n{_tail(build.stderr)}"
        )


def _tail(output: str) -> str:
    return "\n".join(output.splitlines()[-_BUILD_TAIL_LINES:])


_BUILD_TAIL_LINES = 40


def target_services(targets: Sequence[CVETarget]) -> list[str]:
    """The deduplicated compose services of every target: its images and its patched twin."""
    services: list[str] = []
    for target in targets:
        for service in (*target.images, target.patched_image):
            if service not in services:
                services.append(service)
    return services


def _backend_images(targets: Sequence[CVETarget]) -> list[str]:
    return list(dict.fromkeys(tag for target in targets for tag in target.backend_images))
