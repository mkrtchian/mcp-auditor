import dataclasses
import subprocess
import sys
from collections.abc import Awaitable, Callable, Mapping, Sequence
from datetime import date
from typing import Any

import pytest

from evals import holdout_run
from evals.cve_grammar import CVEStatus, RunGrade
from evals.cve_layout_check import LayoutCheck
from evals.cve_places import HOLDOUT_PLACES, load_places
from evals.cve_session_model import GradedAudit
from evals.cve_targets import CVE_TARGETS, CVETarget
from evals.eval_session import TreeState
from evals.holdout_audit import DroppedRun, IncompleteRun
from evals.holdout_conditions import Cutoff, HoldoutConditions
from evals.holdout_results import HoldoutRunResult
from evals.holdout_run import HoldoutDeps, run_holdout
from evals.probe_candidates import Prices
from mcp_auditor.config import Settings
from mcp_auditor.domain.models import AuditReport, ProviderUsage
from tests.unit.support import test_cve_grammar_given as grammar

FILESYSTEM = "CVE-2025-53109"
KUBERNETES = "CVE-2025-53355"
LUNA_PRICE = Prices(input=0.10, cached_input=0.01, output=0.50)
RECORDED_AT = "2026-10-28T09:30:00+00:00"
SETTINGS = Settings(provider="openai", model="gpt-6-luna", judge_model="", reasoning="none")

type Outcome = GradedAudit | IncompleteRun | DroppedRun
type Audit = Callable[[CVETarget], Awaitable[Outcome]]


def a_target(cve_id: str = FILESYSTEM, **changes: Any) -> CVETarget:
    """A real target, since run_holdout plants its kept places and fingerprints its fixture."""
    (target,) = [target for target in CVE_TARGETS if target.cve_id == cve_id]
    return dataclasses.replace(target, **{"tools_filter": None, **changes})


def a_build_exiting(
    monkeypatch: pytest.MonkeyPatch, returncode: int, stdout: str, stderr: str = ""
) -> None:
    def run(command: Sequence[str], **options: object) -> subprocess.CompletedProcess[str]:
        if not options.get("capture_output"):
            print(stdout)
            print(stderr, file=sys.stderr)
            return subprocess.CompletedProcess(command, returncode)
        return subprocess.CompletedProcess(command, returncode, stdout, stderr)

    monkeypatch.setattr(holdout_run.subprocess, "run", run)


def a_report(provider: ProviderUsage, judge: ProviderUsage) -> AuditReport:
    base = grammar.a_report()  # one tool_report, so tools_count is 1
    return base.model_copy(update={"provider_usage": provider, "judge_usage": judge})


def graded(status: CVEStatus, report: AuditReport, **grade_fields: Any) -> GradedAudit:
    return GradedAudit(RunGrade(status=status, **grade_fields), report)


def three_detections() -> list[Outcome]:
    report = a_report(ProviderUsage(input_tokens=10, output_tokens=20), ProviderUsage())
    return [graded(CVEStatus.DETECTED, report, aimed=True) for _ in range(3)]


def scripted(outcomes_by_id: Mapping[str, list[Outcome]]) -> Audit:
    scripts = {cve_id: list(outcomes) for cve_id, outcomes in outcomes_by_id.items()}

    async def audit(target: CVETarget) -> Outcome:
        return scripts[target.cve_id].pop(0)

    return audit


def deps_auditing(
    audit: Audit,
    *,
    check: dict[str, list[str]] | None = None,
    layout: dict[str, LayoutCheck] | None = None,
    throttled: int = 0,
) -> HoldoutDeps:
    checks = check or {}
    layouts = layout or {}

    async def _check(target: CVETarget) -> list[str]:
        return checks.get(target.cve_id, [])

    async def _layout(target: CVETarget) -> LayoutCheck:
        return layouts.get(target.cve_id, LayoutCheck(gave_up=None, breaks=False, unrouted=[]))

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
    )


def deps_reaching_nothing() -> HoldoutDeps:
    async def audit(_target: CVETarget) -> Outcome:
        raise AssertionError("the audit was reached")

    async def check(_target: CVETarget) -> list[str]:
        raise AssertionError("the dead-condition check was reached")

    async def layout(_target: CVETarget) -> LayoutCheck:
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
    )


async def run(
    targets: list[CVETarget],
    deps: HoldoutDeps,
    *,
    dates: dict[str, date] | None = None,
    runs: int = 3,
    concurrency: int = 6,
) -> HoldoutRunResult:
    """`dates=None` discloses every target on 2026-01-01."""
    if dates is None:
        dates = {target.cve_id: date(2026, 1, 1) for target in targets}
    return await run_holdout(
        targets,
        dates,
        _conditions(),
        SETTINGS,
        load_places(HOLDOUT_PLACES),
        census_commit="cafe",
        runs=runs,
        concurrency=concurrency,
        deps=deps,
    )


def _conditions() -> HoldoutConditions:
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
