"""A detection holdout run of the orchestrator on scripted audits and fake ports: no Docker,
no LLM."""

from collections.abc import Awaitable, Callable, Mapping
from datetime import date
from typing import Any

from evals.cve.detection.holdout_audit import DroppedRun, IncompleteRun
from evals.cve.detection.holdout_results import DetectionHoldoutRunResult
from evals.cve.detection.holdout_run import HoldoutDeps, run_holdout_targets
from evals.cve.detection.layout_check import LayoutCheck
from evals.cve.detection.session_model import GradedAudit
from evals.cve.detection.targets import Target
from evals.cve.grammar import RunGrade, TargetStatus
from evals.cve.holdout_conditions import Cutoff, HoldoutConditions
from evals.cve.places import DETECTION_PLACES, load_places
from evals.eval_session import TreeState
from evals.probe.candidates import Prices
from mcp_auditor.config import Settings
from mcp_auditor.domain.models import AuditReport, ProviderUsage
from tests.fakes import FakeContainerSweep
from tests.unit.cve.support import test_cve_grammar_given as grammar
from tests.unit.detection.support.layouts import SOUND_LAYOUT
from tests.unit.support.acceptance_targets import FILESYSTEM, an_acceptance_target

LUNA_PRICE = Prices(input=0.10, cached_input=0.01, output=0.50)
RECORDED_AT = "2026-10-28T09:30:00+00:00"
SETTINGS = Settings(provider="openai", model="gpt-6-luna", judge_model="", reasoning="none")

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
        running_containers=docker.running,
        remove_containers=docker.remove,
        check_networks=lambda: None,
    )


def deps_reaching_nothing() -> HoldoutDeps:
    async def audit(_target: Target) -> Outcome:
        raise AssertionError("the audit was reached")

    async def check(_target: Target) -> list[str]:
        raise AssertionError("the calibration check was reached")

    async def layout(_target: Target) -> LayoutCheck:
        raise AssertionError("the layout observation was reached")

    def rebuild(_services: object) -> None:
        raise AssertionError("the image rebuild was reached")

    def image_ids(_names: object) -> dict[str, str]:
        raise AssertionError("the image ids were read")

    def backend_image_ids(_tags: object) -> dict[str, str]:
        raise AssertionError("the backend image ids were read")

    def read_tree() -> TreeState:
        raise AssertionError("read_tree was reached")

    def clock() -> str:
        raise AssertionError("the clock was read")

    def announce_audits(_audits: int) -> None:
        raise AssertionError("the audits were announced")

    def throttled_requests() -> int:
        raise AssertionError("the throttled requests were read")

    def running_containers(_tags: object) -> list[str]:
        raise AssertionError("the running containers were listed")

    def remove_containers(_containers: object) -> None:
        raise AssertionError("a container was removed")

    return HoldoutDeps(
        audit,
        check,
        layout,
        rebuild,
        image_ids,
        backend_image_ids,
        read_tree,
        clock,
        announce_audits,
        throttled_requests,
        running_containers,
        remove_containers,
        lambda: None,
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
    return await run_holdout_targets(
        targets,
        dates,
        ready_conditions(),
        SETTINGS,
        load_places(DETECTION_PLACES),
        census_commit="cafe",
        runs=runs,
        concurrency=concurrency,
        deps=deps,
    )


def ready_conditions() -> HoldoutConditions:
    return HoldoutConditions(
        chain_budget=3,
        max_chain_steps=5,
        tool_call_timeout=30,
        cutoffs={
            "gpt-6-luna": Cutoff(
                date=date(2026, 5, 18), type="training", source="https://example.test", note=None
            )
        },
        prices={"gpt-6-luna": LUNA_PRICE},
        prices_as_of=date(2026, 10, 15),
    )
