"""The holdout orchestrator, with the audit and the two no-LLM checks injected as fakes: the
per-target assembly, the pre-run drops, the refused-run accounting and the up-front refusals.
No Docker, no LLM."""

import dataclasses
from collections.abc import Awaitable, Callable, Mapping
from datetime import date
from typing import Any

import pytest

from evals.cve_grammar import CVEStatus, RunGrade
from evals.cve_layout_check import LayoutCheck
from evals.cve_places import HOLDOUT_PLACES, load_places
from evals.cve_session_model import GradedAudit
from evals.cve_targets import CVE_TARGETS, CVETarget, LaunchMode
from evals.eval_session import Refused, TreeState
from evals.holdout_audit import DroppedRun, IncompleteRun
from evals.holdout_conditions import Cutoff, HoldoutConditions
from evals.holdout_results import HoldoutRunResult, NotRunCause
from evals.holdout_run import HoldoutDeps, run_holdout, target_services
from evals.probe import call_cost
from evals.probe_candidates import Prices
from mcp_auditor.config import Settings
from mcp_auditor.domain.models import AuditReport, ProviderUsage
from tests.unit.support import test_cve_grammar_given as grammar

PLACES = load_places(HOLDOUT_PLACES)
LUNA_PRICE = Prices(input=0.10, cached_input=0.01, output=0.50)
SETTINGS = Settings(provider="openai", model="gpt-6-luna", judge_model="", reasoning="none")

type Outcome = GradedAudit | IncompleteRun | DroppedRun
type Audit = Callable[[CVETarget], Awaitable[Outcome]]


def _conditions() -> HoldoutConditions:
    return HoldoutConditions(
        chain_budget=3,
        max_chain_steps=5,
        tool_call_timeout=30,
        cutoffs={"gpt-6-luna": Cutoff(date=date(2026, 5, 18), type="training", note=None)},
        prices={"gpt-6-luna": LUNA_PRICE},
        prices_as_of=date(2026, 10, 15),
    )


def _target(cve_index: int = 0, **changes: object) -> CVETarget:
    return dataclasses.replace(CVE_TARGETS[cve_index], tools_filter=None, **changes)


def _report(provider: ProviderUsage, judge: ProviderUsage) -> AuditReport:
    base = grammar.a_report()  # one tool_report, so tools_count is 1
    return base.model_copy(update={"provider_usage": provider, "judge_usage": judge})


def _graded(status: CVEStatus, report: AuditReport, **grade_fields: Any) -> GradedAudit:
    return GradedAudit(RunGrade(status=status, **grade_fields), report)


def _deps(
    audit: Audit,
    *,
    check: dict[str, list[str]] | None = None,
    layout: dict[str, LayoutCheck] | None = None,
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
        read_tree=lambda: TreeState(commit="c0ffee", dirty=False),
    )


def _scripted(outcomes_by_id: Mapping[str, list[Outcome]]) -> Audit:
    scripts = {cve_id: list(outcomes) for cve_id, outcomes in outcomes_by_id.items()}

    async def audit(target: CVETarget) -> Outcome:
        return scripts[target.cve_id].pop(0)

    return audit


def _raising_deps() -> HoldoutDeps:
    async def audit(_target: CVETarget) -> Outcome:
        raise AssertionError("the audit was reached")

    async def check(_target: CVETarget) -> list[str]:
        raise AssertionError("the dead-condition check was reached")

    async def layout(_target: CVETarget) -> LayoutCheck:
        raise AssertionError("the layout observation was reached")

    def rebuild(_services: object) -> None:
        raise AssertionError("the image rebuild was reached")

    def read_tree() -> TreeState:
        raise AssertionError("read_tree was reached")

    return HoldoutDeps(audit, check, layout, rebuild, lambda names: {}, read_tree)


def _three_detections() -> list[Outcome]:
    report = _report(ProviderUsage(input_tokens=10, output_tokens=20), ProviderUsage())
    return [_graded(CVEStatus.DETECTED, report, aimed=True) for _ in range(3)]


async def _run(
    targets: list[CVETarget],
    audit: Audit,
    *,
    check: dict[str, list[str]] | None = None,
    layout: dict[str, LayoutCheck] | None = None,
    runs: int = 3,
) -> HoldoutRunResult:
    dates = {target.cve_id: date(2026, 1, 1) for target in targets}
    return await run_holdout(
        targets,
        dates,
        _conditions(),
        SETTINGS,
        PLACES,
        census_commit="cafe",
        runs=runs,
        deps=_deps(audit, check=check, layout=layout),
    )


def test_target_services_dedups_images_and_patched_twins():
    # filesystem keeps one image, fetch keeps the sentinel sidecar beside its own.
    services = target_services([CVE_TARGETS[0], CVE_TARGETS[3]])
    assert services == ["filesystem", "filesystem-patched", "fetch", "sentinel", "fetch-patched"]


def test_target_services_is_empty_for_no_target():
    assert target_services([]) == []


async def test_a_target_is_assembled_from_its_runs():
    target = _target(2)  # kubernetes, command_execution, NORMAL
    cve_id = target.cve_id
    provider = ProviderUsage(input_tokens=1000, output_tokens=2000)
    judge = ProviderUsage(input_tokens=100, output_tokens=200)
    report = _report(provider, judge)
    outcomes: list[Outcome] = [
        _graded(CVEStatus.DETECTED, report, surfaced_places=frozenset({"etc-shadow"}), aimed=True),
        _graded(
            CVEStatus.DETECTED,
            report,
            surfaced_places=frozenset({"etc-shadow"}),
            unchecked_places=frozenset({"etc-shadow"}),
            status_if_unchecked_missed=CVEStatus.MISSED,
            aimed=True,
        ),
        _graded(CVEStatus.MISSED, report, aimed=True, fail_without_proof=True),
    ]

    result = await _run([target], _scripted({cve_id: outcomes}))

    (target,) = result.targets
    assert target.detected_runs == 2
    assert target.detection_share == pytest.approx(2 / 3)
    assert target.detected_runs_if_unchecked_missed == 1  # the second run misses if unchecked
    assert target.unchecked_places == [[], ["etc-shadow"], []]
    assert target.aimed_runs == 3
    assert target.fail_without_proof_runs == 1
    assert target.incomplete_runs == 0
    assert target.tools_count == 1
    assert target.mechanism_label == "command_execution"
    assert target.run_cost == pytest.approx(3 * call_cost(provider, LUNA_PRICE))


async def test_an_incomplete_run_counts_as_not_detected_and_is_billed():
    target = _target(2)
    cve_id = target.cve_id
    provider = ProviderUsage(input_tokens=1000, output_tokens=2000)
    refused_report = _report(provider, ProviderUsage())
    outcomes: list[Outcome] = [
        _graded(CVEStatus.DETECTED, _report(provider, ProviderUsage()), aimed=True),
        IncompleteRun(refused_report),
        IncompleteRun(refused_report),
    ]

    result = await _run([target], _scripted({cve_id: outcomes}))

    (target,) = result.targets
    assert target.detected_runs == 1
    assert target.incomplete_runs == 2
    assert result.incomplete_run_count == 2
    assert target.run_cost == pytest.approx(3 * call_cost(provider, LUNA_PRICE))


async def test_a_target_dead_on_a_version_is_not_run():
    dead, healthy = _target(2), _target(0)
    dead_id, healthy_id = dead.cve_id, healthy.cve_id

    result = await _run(
        [dead, healthy],
        _scripted({dead_id: [], healthy_id: _three_detections()}),
        check={dead_id: ["patched: exploit 0 still surfaces etc-shadow"]},
    )

    assert [t.cve_id for t in result.targets] == [healthy_id]
    (not_run,) = result.not_run
    assert not_run.cve_id == dead_id
    assert "patched: exploit 0 still surfaces etc-shadow" in not_run.reason
    assert not_run.cause is NotRunCause.PRE_RUN_CHECK


async def test_a_normal_target_the_layout_breaks_is_dropped():
    broken, healthy = _target(2), _target(0)  # both NORMAL
    broken_id, healthy_id = broken.cve_id, healthy.cve_id

    result = await _run(
        [broken, healthy],
        _scripted({broken_id: [], healthy_id: _three_detections()}),
        layout={broken_id: LayoutCheck(gave_up=None, breaks=True, unrouted=[])},
    )

    assert [t.cve_id for t in result.targets] == [healthy_id]
    (not_run,) = result.not_run
    assert not_run.cve_id == broken_id
    assert not_run.reason == "the layout breaks the server under the normal launch"
    assert not_run.cause is NotRunCause.PRE_RUN_CHECK


async def test_a_fallback_target_the_layout_breaks_is_kept():
    target = _target(2, launch_mode=LaunchMode.FALLBACK)
    cve_id = target.cve_id
    report = _report(ProviderUsage(input_tokens=10, output_tokens=20), ProviderUsage())
    outcomes: list[Outcome] = [_graded(CVEStatus.DETECTED, report, aimed=True) for _ in range(3)]

    result = await _run(
        [target],
        _scripted({cve_id: outcomes}),
        layout={cve_id: LayoutCheck(gave_up=None, breaks=True, unrouted=[])},
    )

    (target,) = result.targets
    assert target.ran_in_fallback is True
    assert result.not_run == []


async def test_a_target_whose_run_fails_to_launch_is_dropped_for_the_whole_run():
    sick, healthy = _target(2), _target(0)
    sick_id, healthy_id = sick.cve_id, healthy.cve_id
    report = _report(ProviderUsage(), ProviderUsage())
    launch_failure = DroppedRun(NotRunCause.LAUNCH_FAILURE)
    sick_outcomes: list[Outcome] = [
        _graded(CVEStatus.DETECTED, report, aimed=True),
        launch_failure,
        launch_failure,
    ]

    result = await _run(
        [sick, healthy],
        _scripted({sick_id: sick_outcomes, healthy_id: _three_detections()}),
    )

    assert [t.cve_id for t in result.targets] == [healthy_id]
    (not_run,) = result.not_run
    assert not_run.cve_id == sick_id
    assert not_run.reason == "a run failed to launch after retries"
    assert not_run.cause is NotRunCause.LAUNCH_FAILURE


async def test_a_target_with_any_throttled_run_is_dropped_as_throttled():
    sick, healthy = _target(2), _target(0)
    sick_id, healthy_id = sick.cve_id, healthy.cve_id
    report = _report(ProviderUsage(), ProviderUsage())
    sick_outcomes: list[Outcome] = [
        DroppedRun(NotRunCause.LAUNCH_FAILURE),
        DroppedRun(NotRunCause.THROTTLED),
        _graded(CVEStatus.DETECTED, report, aimed=True),
    ]

    result = await _run(
        [sick, healthy],
        _scripted({sick_id: sick_outcomes, healthy_id: _three_detections()}),
    )

    (not_run,) = result.not_run
    assert not_run.cve_id == sick_id
    assert not_run.reason == "throttled by the model provider past every retry"
    assert not_run.cause is NotRunCause.THROTTLED


async def test_a_drawn_target_with_a_tools_filter_refuses_before_any_check():
    target = dataclasses.replace(CVE_TARGETS[2], tools_filter=frozenset({"kubectl_generic"}))

    async def audit(_target: CVETarget) -> Outcome:  # must never be reached
        raise AssertionError("the audit ran before the tools-filter refusal")

    with pytest.raises(Refused, match="tools filter"):
        await _run([target], audit)


async def test_tracing_refuses_before_any_container(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("LANGSMITH_TRACING", "1")

    async def audit(_target: CVETarget) -> Outcome:
        raise AssertionError("the audit ran despite tracing being on")

    with pytest.raises(Refused, match="trace"):
        await _run([_target(2)], audit)


async def test_a_target_absent_from_the_census_refuses_before_any_dep():
    target = _target(2)

    with pytest.raises(Refused, match="census"):
        await run_holdout(
            [target],
            {},  # the drawn target's cve_id is absent
            _conditions(),
            SETTINGS,
            PLACES,
            census_commit="cafe",
            deps=_raising_deps(),
        )


async def test_a_dirty_tree_refuses_before_rebuild_and_audit():
    target = _target(2)
    deps = dataclasses.replace(
        _raising_deps(), read_tree=lambda: TreeState(commit="c0ffee", dirty=True)
    )

    with pytest.raises(Refused, match="dirty"):
        await run_holdout(
            [target],
            {target.cve_id: date(2026, 1, 1)},
            _conditions(),
            SETTINGS,
            PLACES,
            census_commit="cafe",
            deps=deps,
        )


async def test_every_target_dropped_refuses_with_the_reasons():
    dead, broken = _target(2), _target(0)
    dead_id, broken_id = dead.cve_id, broken.cve_id

    with pytest.raises(Refused, match="no target survived") as caught:
        await _run(
            [dead, broken],
            _scripted({dead_id: [], broken_id: []}),
            check={dead_id: ["patched: exploit 0 still surfaces etc-shadow"]},
            layout={broken_id: LayoutCheck(gave_up=None, breaks=True, unrouted=[])},
        )

    reasons = caught.value.reasons
    assert any("etc-shadow" in reason for reason in reasons)
    assert any("the layout breaks" in reason for reason in reasons)


async def test_a_target_with_an_unknown_kept_place_refuses_before_any_dep():
    target = _target(2, kept_places=("no-such-place",))

    with pytest.raises(Refused, match="no such place"):
        await run_holdout(
            [target],
            {target.cve_id: date(2026, 1, 1)},
            _conditions(),
            SETTINGS,
            PLACES,
            census_commit="cafe",
            deps=_raising_deps(),
        )
