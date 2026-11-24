"""The detection holdout run orchestrator: audit every holdout target at one commit under the rule's
run conditions, keep no per-case trace, and assemble the per-target and whole-run results.

A sibling of the gated session of the acceptance layer (`evals.cve.detection.session`): no gate,
no baseline, no judged-case export, the opposite missed model call policy (`holdout_audit`). The
targets are passed in, never read from `HOLDOUT_TARGETS` here, so the tests hand it crafted ones.
The heavy I/O is grouped in `HoldoutDeps`, faked by the unit tests and built from the live
settings by `holdout_command_deps.default_deps`.
"""

import dataclasses
from collections.abc import Awaitable, Callable, Coroutine, Mapping, Sequence
from dataclasses import dataclass
from datetime import date
from typing import Any, Protocol

from evals.cve.detection.baseline import fixture_fingerprint, grammar_fingerprint
from evals.cve.detection.holdout_assembly import assemble_target
from evals.cve.detection.holdout_audit import DroppedRun, IncompleteRun
from evals.cve.detection.holdout_pre_run_check import check_before_run
from evals.cve.detection.holdout_results import (
    DROPPED_RUN_REASONS,
    DetectionHoldoutRunResult,
    HoldoutTargetResult,
    NotRunTarget,
)
from evals.cve.detection.layout_check import LayoutCheck
from evals.cve.detection.session_model import GradedAudit
from evals.cve.detection.targets import Target, target_services
from evals.cve.holdout_conditions import (
    HOLDOUT_TEST_BUDGET,
    HoldoutConditions,
    run_model_ids,
)
from evals.cve.images import image_tag
from evals.cve.places import Places, kept_records
from evals.cve.run_files import RunInterrupted
from evals.cve.run_images import (
    ContainerSweep,
    refuse_running_containers,
    refuse_without_closed_networks,
    sweep_containers,
)
from evals.cve.run_interruption import first_failure, sibling_runs
from evals.eval_session import Refused, TreeState
from evals.model_conditions import ModelConditions
from evals.tracing import TRACING_ON, tracing_enabled
from mcp_auditor.config import Settings

HOLDOUT_RUNS = 3  # detection-suite-rule.md, Run conditions and statistic, lowerable to 1 and logged
HOLDOUT_CONCURRENCY = 6
DETECTION_HOLDOUT_RUN_REFUSED = "detection holdout run refused"

type Audit = Callable[[Target], Awaitable[GradedAudit | IncompleteRun | DroppedRun]]


@dataclass(frozen=True)
class HoldoutDeps:
    audit: Audit
    # the out-of-calibration reasons on both versions
    check: Callable[[Target], Awaitable[list[str]]]
    layout: Callable[[Target], Awaitable[LayoutCheck]]
    rebuild: Callable[[Sequence[str]], None]
    image_ids: Callable[[Sequence[str]], dict[str, str]]
    backend_image_ids: Callable[[Sequence[str]], dict[str, str]]
    read_tree: Callable[[], TreeState]
    clock: Callable[[], str]  # ISO timestamp for recorded_at
    announce_audits: Callable[[int], None]
    throttled_requests: Callable[[], int]
    sweep: ContainerSweep
    check_networks: Callable[[], None]


@dataclass(frozen=True)
class HoldoutRunInputs:
    targets: Sequence[Target]
    disclosure_dates: Mapping[str, date]
    census_commit: str
    conditions: HoldoutConditions
    settings: Settings
    places: Places
    runs: int
    concurrency: int

    @property
    def model_ids(self) -> list[str]:
        return run_model_ids(self.settings)


class RunHoldoutTargets(Protocol):
    def __call__(
        self, inputs: HoldoutRunInputs, /, *, deps: HoldoutDeps
    ) -> Coroutine[Any, Any, DetectionHoldoutRunResult]: ...


async def run_holdout_targets(
    inputs: HoldoutRunInputs, *, deps: HoldoutDeps
) -> DetectionHoldoutRunResult:
    refuse_tracing()
    _refuse_tools_filter(inputs.targets)
    _refuse_missing_census(inputs.targets, inputs.disclosure_dates)
    _refuse_unknown_places(inputs.targets, inputs.places)
    inputs.conditions.require_ready(inputs.model_ids)
    tree = deps.read_tree()
    _refuse_dirty_tree(tree)
    refuse_without_closed_networks(deps.check_networks)
    services = target_services(list(inputs.targets))
    tags = [image_tag(service) for service in services]
    _refuse_running_containers(deps, tags)
    deps.rebuild(services)
    _refuse_running_containers(deps, tags)
    try:
        return await _run_surviving(inputs, deps, tree)
    finally:
        sweep_containers(tags, deps.sweep)


def _refuse_running_containers(deps: HoldoutDeps, tags: Sequence[str]) -> None:
    refuse_running_containers(deps.sweep.running_containers(tags), DETECTION_HOLDOUT_RUN_REFUSED)


async def _run_surviving(
    inputs: HoldoutRunInputs, deps: HoldoutDeps, tree: TreeState
) -> DetectionHoldoutRunResult:
    pre_run = await check_before_run(inputs.targets, deps.check, deps.layout)
    assembled, dropped, failure = await _run_all(pre_run.surviving, deps, inputs)
    all_not_run = [*pre_run.not_run, *dropped]
    if failure is not None:
        partial = _assemble_run(inputs, deps, assembled, all_not_run, tree)
        raise RunInterrupted(
            dataclasses.replace(partial, partial=True, second_pass=pre_run.second_pass), failure
        )
    if not assembled:
        raise Refused(
            DETECTION_HOLDOUT_RUN_REFUSED,
            ["no target survived the pre-run check", *(entry.reason for entry in all_not_run)],
        )
    result = _assemble_run(inputs, deps, assembled, all_not_run, tree)
    return dataclasses.replace(result, second_pass=pre_run.second_pass)


def refuse_tracing() -> None:
    if tracing_enabled():
        raise Refused(
            DETECTION_HOLDOUT_RUN_REFUSED,
            [f"{TRACING_ON}; a detection holdout run keeps no trace"],
        )


def _refuse_tools_filter(targets: Sequence[Target]) -> None:
    filtered = [target.flaw_id for target in targets if target.tools_filter is not None]
    if filtered:
        raise Refused(
            DETECTION_HOLDOUT_RUN_REFUSED,
            [f"the rule runs with no tools filter, but {name} carries one" for name in filtered],
        )


def _refuse_missing_census(targets: Sequence[Target], dates: Mapping[str, date]) -> None:
    missing = [target.flaw_id for target in targets if target.flaw_id not in dates]
    if missing:
        raise Refused(
            DETECTION_HOLDOUT_RUN_REFUSED,
            [f"{name} is drawn but absent from the census" for name in missing],
        )


def _refuse_unknown_places(targets: Sequence[Target], places: Places) -> None:
    reasons: list[str] = []
    for target in targets:
        try:
            target.planting_spec(kept_records(target.kept_places, places))
        except ValueError as exc:
            reasons.append(f"{target.flaw_id}: {exc}")
    if reasons:
        raise Refused(DETECTION_HOLDOUT_RUN_REFUSED, reasons)


def _refuse_dirty_tree(tree: TreeState) -> None:
    if tree.dirty:
        raise Refused(
            DETECTION_HOLDOUT_RUN_REFUSED,
            ["the git tree is dirty: a detection holdout run publishes from a clean tree"],
        )


async def _run_all(
    surviving: Sequence[Target], deps: HoldoutDeps, inputs: HoldoutRunInputs
) -> tuple[list[tuple[Target, HoldoutTargetResult]], list[NotRunTarget], BaseException | None]:
    """The finished targets, assembled or dropped, and the exception that stopped the run, if
    any: a first exception out of a target's runs cancels every target still in flight."""
    deps.announce_audits(len(surviving) * inputs.runs)
    finished, failure = await first_failure(
        surviving, lambda target: _run_target(target, deps.audit, inputs.runs)
    )
    prices = inputs.conditions.audit_prices(
        inputs.settings.resolve_model(), inputs.settings.resolve_judge_model()
    )
    assembled: list[tuple[Target, HoldoutTargetResult]] = []
    dropped: list[NotRunTarget] = []
    for target, outcomes in finished:
        if isinstance(outcomes, DroppedRun):
            reason = DROPPED_RUN_REASONS[outcomes.cause]
            dropped.append(NotRunTarget(target.flaw_id, reason, outcomes.cause))
        else:
            disclosure_date = inputs.disclosure_dates[target.flaw_id]
            result = assemble_target(target, outcomes, disclosure_date, prices)
            assembled.append((target, result))
    return assembled, dropped, failure


async def _run_target(
    target: Target, audit: Audit, runs: int
) -> list[GradedAudit | IncompleteRun] | DroppedRun:
    outcomes = await sibling_runs(runs, lambda: audit(target))
    causes = {outcome.cause for outcome in outcomes if isinstance(outcome, DroppedRun)}
    if causes:
        return DroppedRun.from_causes(causes)
    return [outcome for outcome in outcomes if not isinstance(outcome, DroppedRun)]


def _assemble_run(
    inputs: HoldoutRunInputs,
    deps: HoldoutDeps,
    assembled: Sequence[tuple[Target, HoldoutTargetResult]],
    not_run: list[NotRunTarget],
    tree: TreeState,
) -> DetectionHoldoutRunResult:
    targets = [target for target, _ in assembled]
    results = [result for _, result in assembled]
    return DetectionHoldoutRunResult(
        runs=inputs.runs,
        budget=HOLDOUT_TEST_BUDGET,
        **ModelConditions.of(inputs.settings).model_dump(),
        cutoffs={model_id: inputs.conditions.cutoffs[model_id] for model_id in inputs.model_ids},
        chain_budget=inputs.conditions.chain_budget,
        max_chain_steps=inputs.conditions.max_chain_steps,
        tool_call_timeout=inputs.conditions.tool_call_timeout,
        grammar_fingerprint=grammar_fingerprint(),
        fixture_fingerprints={t.flaw_id: fixture_fingerprint(t, inputs.places) for t in targets},
        commit=tree.commit,
        census_commit=inputs.census_commit,
        image_ids={
            **deps.image_ids(target_services(targets)),
            **deps.backend_image_ids(_backend_images(targets)),
        },
        recorded_at=deps.clock(),
        targets=results,
        not_run=not_run,
        incomplete_run_count=sum(result.incomplete_runs for result in results),
        total_cost=sum(result.run_cost for result in results),
        prices_as_of=inputs.conditions.prices_as_of,
        concurrency=inputs.concurrency,
        throttled_requests=deps.throttled_requests(),
    )


def _backend_images(targets: Sequence[Target]) -> list[str]:
    return list(dict.fromkeys(tag for target in targets for tag in target.backend_images))
