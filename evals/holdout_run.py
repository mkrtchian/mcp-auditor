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
from datetime import UTC, date, datetime

from evals.concurrency import bounded
from evals.cve_audit import RunOverrides, attempt_once, build_auditor
from evals.cve_baseline import (
    backend_image_ids,
    fixture_fingerprint,
    grammar_fingerprint,
    image_ids,
)
from evals.cve_calibration import check_target
from evals.cve_images import COMPOSE_FILE
from evals.cve_layout_check import LayoutCheck
from evals.cve_places import Places, kept_records
from evals.cve_session_model import GradedAudit
from evals.cve_targets import CVETarget
from evals.eval_runs import tracing_enabled
from evals.eval_session import Refused, TreeState, read_tree
from evals.holdout_assembly import assemble_target, holdout_prices
from evals.holdout_audit import DroppedRun, IncompleteRun, holdout_audit
from evals.holdout_conditions import HoldoutConditions
from evals.holdout_results import (
    DROPPED_RUN_REASONS,
    HoldoutRunResult,
    HoldoutTargetResult,
    NotRunCause,
    NotRunTarget,
)
from evals.holdout_vetting import observe_layout, vet_all
from evals.metrics import SessionThrottles
from mcp_auditor.config import Settings

HOLDOUT_RUNS = 3  # holdout-rule.md:235, lowerable to 1 and logged
HOLDOUT_BUDGET = 10  # holdout-rule.md:227, a constant, not a flag
HOLDOUT_CONCURRENCY = 6
_BUILD_TAIL_LINES = 40

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
    clock: Callable[[], str]  # ISO timestamp for recorded_at
    announce_audits: Callable[[int], None]
    throttled_requests: Callable[[], int]


@dataclass(frozen=True)
class _RunContext:
    conditions: HoldoutConditions
    settings: Settings
    places: Places
    disclosure_dates: Mapping[str, date]
    model_ids: list[str]
    runs: int
    concurrency: int
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
        conditions, settings, places, disclosure_dates, model_ids, runs, concurrency, census_commit
    )
    conditions.require_ready(model_ids)
    deps = deps or default_deps(places, holdout_overrides(conditions), concurrency)
    tree = deps.read_tree()
    _refuse_dirty_tree(tree)
    deps.rebuild(target_services(list(targets)))
    not_run, surviving = await vet_all(targets, deps.check, deps.layout)
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


def _refuse_missing_census(targets: Sequence[CVETarget], dates: Mapping[str, date]) -> None:
    missing = [target.cve_id for target in targets if target.cve_id not in dates]
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


def holdout_overrides(conditions: HoldoutConditions) -> RunOverrides:
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
        return await observe_layout(target, places)

    return HoldoutDeps(
        bounded(audit, concurrency),
        bounded(check, concurrency),
        bounded(layout, concurrency),
        rebuild_images,
        image_ids,
        backend_image_ids,
        read_tree,
        lambda: datetime.now(UTC).isoformat(),
        lambda audits: None,
        lambda: throttles.requests,
    )


async def _run_all(
    surviving: Sequence[CVETarget], deps: HoldoutDeps, ctx: _RunContext
) -> tuple[list[tuple[CVETarget, HoldoutTargetResult]], list[NotRunTarget]]:
    deps.announce_audits(len(surviving) * ctx.runs)
    runs_per = await asyncio.gather(
        *(_run_target(target, deps.audit, ctx.runs) for target in surviving)
    )
    prices = holdout_prices(ctx.conditions, ctx.settings)
    assembled: list[tuple[CVETarget, HoldoutTargetResult]] = []
    dropped: list[NotRunTarget] = []
    for target, outcomes in zip(surviving, runs_per, strict=True):
        if isinstance(outcomes, DroppedRun):
            reason = DROPPED_RUN_REASONS[outcomes.cause]
            dropped.append(NotRunTarget(target.cve_id, reason, outcomes.cause))
        else:
            result = assemble_target(target, outcomes, ctx.disclosure_dates[target.cve_id], prices)
            assembled.append((target, result))
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
        recorded_at=deps.clock(),
        targets=results,
        not_run=not_run,
        incomplete_run_count=sum(result.incomplete_runs for result in results),
        total_cost=sum(result.run_cost for result in results),
        prices_as_of=ctx.conditions.prices_as_of,
        concurrency=ctx.concurrency,
        throttled_requests=deps.throttled_requests(),
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
