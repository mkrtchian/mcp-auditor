"""A detection holdout run of the orchestrator on scripted audits and fake ports: no Docker,
no LLM."""

from collections.abc import Awaitable, Callable, Mapping
from datetime import date
from typing import Any

import tests.unit.support.grammar_inputs as grammar
from evals.cve.detection.holdout_audit import DroppedRun, IncompleteRun
from evals.cve.detection.holdout_results import DetectionHoldoutRunResult
from evals.cve.detection.holdout_run import HoldoutDeps, HoldoutRunInputs, run_holdout_targets
from evals.cve.detection.layout_check import LayoutCheck
from evals.cve.detection.session_model import GradedAudit
from evals.cve.detection.targets import Target
from evals.cve.grammar import RunGrade, TargetStatus
from evals.cve.places import DETECTION_PLACES, load_places
from evals.cve.run_images import ContainerSweep
from evals.eval_session import TreeState
from mcp_auditor.domain.models import AuditReport, ProviderUsage
from tests.fakes import FakeContainerSweep
from tests.unit.detection.support.layouts import SOUND_LAYOUT
from tests.unit.support.acceptance_targets import FILESYSTEM, an_acceptance_target
from tests.unit.support.holdout_run_conditions import SETTINGS, ready_conditions
from tests.unit.support.unreached import unreached

RECORDED_AT = "2026-10-28T09:30:00+00:00"

type Outcome = GradedAudit | IncompleteRun | DroppedRun
type Audit = Callable[[Target], Awaitable[Outcome]]


def a_target(flaw_id: str = FILESYSTEM, **changes: Any) -> Target:
    """A real target, since run_holdout_targets plants its kept places and fingerprints its
    fixture."""
    return an_acceptance_target(flaw_id, **{"tools_filter": None, **changes})


def three_detections() -> list[Outcome]:
    report = a_report(ProviderUsage(input_tokens=10, output_tokens=20), ProviderUsage())
    return [graded(TargetStatus.DETECTED, report, aimed=True) for _ in range(3)]


def a_report(provider: ProviderUsage, judge: ProviderUsage) -> AuditReport:
    base = grammar.a_report()  # one tool_report, so tools_count is 1
    return base.model_copy(update={"provider_usage": provider, "judge_usage": judge})


def graded(status: TargetStatus, report: AuditReport, **grade_fields: Any) -> GradedAudit:
    return GradedAudit(RunGrade(status=status, **grade_fields), report)


def scripted(outcomes_by_id: Mapping[str, list[Outcome]]) -> Audit:
    scripts = {flaw_id: list(outcomes) for flaw_id, outcomes in outcomes_by_id.items()}

    async def audit(target: Target) -> Outcome:
        return scripts[target.flaw_id].pop(0)

    return audit


def deps_auditing(
    audit: Audit,
    *,
    check: dict[str, list[str]] | None = None,
    layout: dict[str, LayoutCheck] | None = None,
    throttled: int = 0,
    containers: FakeContainerSweep | None = None,
) -> HoldoutDeps:
    checks = check or {}
    layouts = layout or {}
    docker = containers or FakeContainerSweep()

    async def _check(target: Target) -> list[str]:
        return checks.get(target.flaw_id, [])

    async def _layout(target: Target) -> LayoutCheck:
        return layouts.get(target.flaw_id, SOUND_LAYOUT)

    return HoldoutDeps(
        audit=audit,
        check=_check,
        layout=_layout,
        rebuild=lambda services: None,
        image_ids=lambda names: {name: f"sha256:{name}" for name in names},
        backend_image_ids=lambda tags: {tag: f"sha256:{tag}" for tag in tags},
        read_tree=lambda: TreeState(commit="c0ffee", dirty=False),
        clock=lambda: RECORDED_AT,
        announce_audits=lambda audits: None,
        throttled_requests=lambda: throttled,
        sweep=docker.sweep,
        check_networks=lambda: None,
    )


def deps_reaching_nothing() -> HoldoutDeps:
    return HoldoutDeps(
        audit=unreached("the audit"),
        check=unreached("the calibration check"),
        layout=unreached("the layout observation"),
        rebuild=unreached("the image rebuild"),
        image_ids=unreached("the image id lookup"),
        backend_image_ids=unreached("the backend image id lookup"),
        read_tree=unreached("the tree read"),
        clock=unreached("the clock"),
        announce_audits=unreached("the audit announcement"),
        throttled_requests=unreached("the throttled request count"),
        sweep=ContainerSweep(unreached("the container listing"), unreached("a container removal")),
        check_networks=lambda: None,
    )


async def run(
    targets: list[Target],
    deps: HoldoutDeps,
    *,
    dates: dict[str, date] | None = None,
    runs: int = 3,
    concurrency: int = 6,
) -> DetectionHoldoutRunResult:
    """`dates=None` discloses every target on 2026-01-01."""
    if dates is None:
        dates = {target.flaw_id: date(2026, 1, 1) for target in targets}
    inputs = HoldoutRunInputs(
        targets=targets,
        disclosure_dates=dates,
        census_commit="cafe",
        conditions=ready_conditions(),
        settings=SETTINGS,
        places=load_places(DETECTION_PLACES),
        runs=runs,
        concurrency=concurrency,
    )
    return await run_holdout_targets(inputs, deps=deps)
