import pytest

import tests.unit.support.test_detection_gate_given as given
from evals.cve.detection.baseline import DetectionBaseline
from evals.cve.detection.gate import (
    TargetOutcome,
    apply_retests,
    compare_target,
    condition_mismatches,
    decide,
    exit_code,
)
from evals.cve.grammar import TargetStatus
from evals.gate import RetestRule
from evals.gate_outcome import GateOutcome

DETECTED = given.DETECTED
MISSED = given.MISSED


def test_a_target_without_a_file_has_no_baseline():
    comparison = compare_target(None, given.a_candidate())

    assert comparison.outcome == TargetOutcome.NO_BASELINE


def test_a_changed_fixture_leaves_the_comparison_with_the_target_reset():
    comparison = compare_target(given.a_gated_baseline(), given.a_candidate(fixture="another"))

    assert comparison.outcome == TargetOutcome.FIXTURE_CHANGED
    assert comparison.detail is not None
    assert "delete evals/baselines/detection/CVE-2025-53355.json" in comparison.detail
    assert "--flaw CVE-2025-53355" in comparison.detail


@pytest.mark.parametrize(
    ("baseline", "outcome"),
    [
        (given.a_gated_baseline(), TargetOutcome.INCOMPLETE),
        (given.a_confirmed_baseline([DETECTED] * 5 + [MISSED]), TargetOutcome.NOT_GATED),
    ],
    ids=["gated", "not gated"],
)
def test_an_incomplete_candidate(baseline: DetectionBaseline, outcome: TargetOutcome):
    comparison = compare_target(baseline, given.a_candidate([DETECTED], completed=False))

    assert comparison.outcome == outcome


def test_an_unconfirmed_file_does_not_gate_and_asks_to_be_confirmed_or_deleted():
    comparison = compare_target(given.an_unconfirmed_baseline(), given.a_candidate([MISSED] * 3))

    assert comparison.outcome == TargetOutcome.NOT_GATED
    assert comparison.detail is not None
    assert "unconfirmed" in comparison.detail
    assert given.RECORDED_COMMIT in comparison.detail
    assert "confirm it" in comparison.detail
    assert "delete it" in comparison.detail


def test_a_confirmed_file_with_a_miss_does_not_gate():
    baseline = given.a_confirmed_baseline([DETECTED] * 5 + [MISSED])

    comparison = compare_target(baseline, given.a_candidate([MISSED] * 3))

    assert comparison.outcome == TargetOutcome.NOT_GATED


@pytest.mark.parametrize(
    ("runs", "outcome"),
    [
        ([DETECTED] * 3, TargetOutcome.HELD),
        ([DETECTED, MISSED, DETECTED], TargetOutcome.PENDING_RETEST),
    ],
    ids=["detected", "missed once"],
)
def test_a_gated_target(runs: list[TargetStatus], outcome: TargetOutcome):
    comparison = compare_target(given.a_gated_baseline(), given.a_candidate(runs))

    assert comparison.outcome == outcome
    assert comparison.candidate_runs == runs


@pytest.mark.parametrize(
    ("baseline", "runs", "outcome"),
    [
        (given.a_gated_baseline(), [DETECTED] * 3, TargetOutcome.HELD),
        (given.a_gated_baseline(), [DETECTED, MISSED, DETECTED], TargetOutcome.PENDING_RETEST),
        (
            given.a_confirmed_baseline([DETECTED] * 5 + [MISSED]),
            [MISSED] * 3,
            TargetOutcome.NOT_GATED,
        ),
    ],
    ids=["held", "pending", "not gated"],
)
def test_a_comparison_carries_the_baseline_runs(
    baseline: DetectionBaseline, runs: list[TargetStatus], outcome: TargetOutcome
):
    comparison = compare_target(baseline, given.a_candidate(runs))

    assert comparison.outcome == outcome
    assert comparison.baseline_runs == baseline.runs


def test_a_comparison_without_a_baseline_carries_no_baseline_runs():
    comparison = compare_target(None, given.a_candidate())

    assert comparison.baseline_runs == []


def test_apply_retests_keeps_the_baseline_runs():
    pending = compare_target(given.a_gated_baseline(), given.a_candidate([MISSED] * 3))

    retested = apply_retests(pending, [True] * 4, RetestRule())

    assert retested.outcome == TargetOutcome.REGRESSION
    assert retested.baseline_runs == [DETECTED] * 6


@pytest.mark.parametrize(
    ("retests", "outcome"),
    [
        ([True] * 4, TargetOutcome.REGRESSION),
        ([False, False], TargetOutcome.MISS_NOT_REPRODUCED),
        ([True, None], TargetOutcome.INCOMPLETE),
    ],
    ids=["reproduced", "cleared", "retest incomplete"],
)
def test_apply_retests_decides_the_retests(retests: list[bool | None], outcome: TargetOutcome):
    pending = given.a_comparison(TargetOutcome.PENDING_RETEST)

    retested = apply_retests(pending, retests, RetestRule())

    assert retested.outcome == outcome


def test_apply_retests_keeps_the_retests():
    pending = given.a_comparison(TargetOutcome.PENDING_RETEST)

    retested = apply_retests(pending, [True, False, True, True, True], RetestRule())

    assert retested.retests == [True, False, True, True, True]


def test_matching_conditions_have_no_mismatch():
    baselines = {given.CVE_ID: given.a_gated_baseline()}

    assert condition_mismatches(baselines, given.conditions()) == []


def test_a_condition_mismatch_is_not_comparable_and_names_the_file_and_field():
    baselines = {given.CVE_ID: given.a_gated_baseline()}
    mismatches = condition_mismatches(baselines, given.conditions(budget=20))

    result = decide([given.a_comparison(TargetOutcome.HELD)], mismatches)

    assert result.outcome == GateOutcome.NOT_COMPARABLE
    reasons = "\n".join(result.reasons)
    assert "CVE-2025-53355.json" in reasons
    assert "budget" in reasons
    assert "delete evals/baselines/detection/" in reasons


def test_a_gated_incomplete_target_is_not_comparable():
    result = decide([given.a_comparison(TargetOutcome.INCOMPLETE)], [])

    assert result.outcome == GateOutcome.NOT_COMPARABLE
    assert any(given.CVE_ID in reason for reason in result.reasons)


def test_a_not_run_target_is_not_comparable():
    result = decide([given.a_comparison(TargetOutcome.NOT_RUN)], [])

    assert result.outcome == GateOutcome.NOT_COMPARABLE
    assert any(given.CVE_ID in reason for reason in result.reasons)


@pytest.mark.parametrize(
    "baseline",
    [None, given.a_gated_baseline()],
    ids=["no baseline", "gated"],
)
def test_a_run_that_depends_on_unchecked_credits_is_not_comparable(
    baseline: DetectionBaseline | None,
):
    candidate = given.a_candidate([DETECTED] * 3, depends_on_unchecked=True)

    comparison = compare_target(baseline, candidate)

    assert comparison.outcome == TargetOutcome.UNCHECKED_DECIDES
    assert decide([comparison], []).outcome == GateOutcome.NOT_COMPARABLE


def test_unchecked_credits_that_change_no_status_stay_comparable():
    candidate = given.a_candidate([DETECTED] * 3, depends_on_unchecked=False)

    comparison = compare_target(given.a_gated_baseline(), candidate)

    assert comparison.outcome == TargetOutcome.HELD


def test_an_undecided_retest_is_not_comparable():
    pending = given.a_comparison(TargetOutcome.PENDING_RETEST)
    undecided = apply_retests(pending, [True, True], RetestRule())

    result = decide([undecided], [])

    assert result.outcome == GateOutcome.NOT_COMPARABLE
    assert any(given.CVE_ID in reason for reason in result.reasons)


def test_a_no_baseline_incomplete_target_leaves_the_run_comparable():
    baseline = given.a_confirmed_baseline([DETECTED] * 5 + [MISSED])
    comparison = compare_target(baseline, given.a_candidate([DETECTED], completed=False))

    assert decide([comparison], []).outcome == GateOutcome.GREEN


def test_a_regression_is_red_and_named():
    comparisons = [
        given.a_comparison(TargetOutcome.HELD, flaw_id="CVE-2025-53109"),
        given.a_comparison(TargetOutcome.REGRESSION),
    ]

    result = decide(comparisons, [])

    assert result.outcome == GateOutcome.RED
    assert any(given.CVE_ID in reason for reason in result.reasons)


@pytest.mark.parametrize(
    "outcomes",
    [
        [TargetOutcome.NO_BASELINE, TargetOutcome.NOT_GATED],
        [TargetOutcome.FIXTURE_CHANGED],
        [TargetOutcome.HELD, TargetOutcome.MISS_NOT_REPRODUCED],
    ],
    ids=["nothing gated", "fixture changed", "held and cleared"],
)
def test_green(outcomes: list[TargetOutcome]):
    comparisons = [
        given.a_comparison(outcome, flaw_id=f"CVE-2025-{index}")
        for index, outcome in enumerate(outcomes)
    ]

    assert decide(comparisons, []).outcome == GateOutcome.GREEN


@pytest.mark.parametrize(
    ("outcome", "code"),
    [(GateOutcome.GREEN, 0), (GateOutcome.RED, 1), (GateOutcome.NOT_COMPARABLE, 3)],
)
def test_exit_code(outcome: GateOutcome, code: int):
    assert exit_code(outcome) == code


def test_a_gated_miss_waits_for_its_retests():
    pending = compare_target(given.a_gated_baseline(), given.a_candidate([MISSED] * 3))

    assert pending.model_dump(mode="json")["outcome"] == "pending_retest"


def test_the_gate_outcome_is_the_shared_gate_outcome():
    result = decide([given.a_comparison(TargetOutcome.HELD)], [])

    assert result.outcome is GateOutcome.GREEN
