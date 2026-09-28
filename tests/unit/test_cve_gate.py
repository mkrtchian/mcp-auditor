import pytest

import tests.unit.support.test_cve_gate_given as given
from evals.cve_baseline import CVETargetBaseline
from evals.cve_gate import (
    CVEGateVerdict,
    TargetOutcome,
    compare_target,
    condition_mismatches,
    exit_code,
    judge,
    settle,
)
from evals.cve_grammar import CVEStatus
from evals.gate import ReplayRule

DETECTED = given.DETECTED
EXECUTION_ONLY = given.EXECUTION_ONLY
MISSED = given.MISSED


def test_a_target_without_a_file_has_no_baseline():
    comparison = compare_target(None, given.a_candidate())

    assert comparison.outcome == TargetOutcome.NO_BASELINE


def test_a_changed_fixture_leaves_the_comparison_with_the_target_reset():
    comparison = compare_target(given.a_gated_baseline(), given.a_candidate(fixture="another"))

    assert comparison.outcome == TargetOutcome.FIXTURE_CHANGED
    assert comparison.detail is not None
    assert "delete evals/baselines/cve/CVE-2025-53355.json" in comparison.detail
    assert "--cve CVE-2025-53355" in comparison.detail


@pytest.mark.parametrize(
    ("baseline", "outcome"),
    [
        (given.a_gated_baseline(), TargetOutcome.INCOMPLETE),
        (given.a_confirmed_baseline([DETECTED] * 5 + [MISSED]), TargetOutcome.NOT_GATED),
    ],
    ids=["gated", "not gated"],
)
def test_an_incomplete_candidate(baseline: CVETargetBaseline, outcome: TargetOutcome):
    comparison = compare_target(baseline, given.a_candidate([DETECTED], completed=False))

    assert comparison.outcome == outcome


def test_an_exploratory_file_does_not_gate_and_asks_to_be_confirmed_or_deleted():
    comparison = compare_target(given.an_exploratory_baseline(), given.a_candidate([MISSED] * 3))

    assert comparison.outcome == TargetOutcome.NOT_GATED
    assert comparison.detail is not None
    assert "exploratory" in comparison.detail
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
        ([EXECUTION_ONLY, DETECTED, EXECUTION_ONLY], TargetOutcome.HELD),
        ([DETECTED, MISSED, DETECTED], TargetOutcome.PENDING_REPLAY),
    ],
    ids=["detected", "execution only still detects", "missed once"],
)
def test_a_gated_target(runs: list[CVEStatus], outcome: TargetOutcome):
    comparison = compare_target(given.a_gated_baseline(), given.a_candidate(runs))

    assert comparison.outcome == outcome
    assert comparison.candidate_runs == runs


@pytest.mark.parametrize(
    ("replays", "outcome"),
    [
        ([True] * 4, TargetOutcome.REGRESSION),
        ([False, False], TargetOutcome.MISS_NOT_REPRODUCED),
        ([True, None], TargetOutcome.INCOMPLETE),
    ],
    ids=["reproduced", "cleared", "replay incomplete"],
)
def test_settle_decides_the_replays(replays: list[bool | None], outcome: TargetOutcome):
    pending = given.a_comparison(TargetOutcome.PENDING_REPLAY)

    settled = settle(pending, replays, ReplayRule())

    assert settled.outcome == outcome


def test_settle_keeps_the_replays():
    pending = given.a_comparison(TargetOutcome.PENDING_REPLAY)

    settled = settle(pending, [True, False, True, True, True], ReplayRule())

    assert settled.replays == [True, False, True, True, True]


def test_matching_conditions_have_no_mismatch():
    baselines = {given.CVE_ID: given.a_gated_baseline()}

    assert condition_mismatches(baselines, given.conditions()) == []


def test_a_condition_mismatch_is_not_comparable_and_names_the_file_and_field():
    baselines = {given.CVE_ID: given.a_gated_baseline()}
    mismatches = condition_mismatches(baselines, given.conditions(budget=20))

    result = judge([given.a_comparison(TargetOutcome.HELD)], mismatches)

    assert result.verdict == CVEGateVerdict.NOT_COMPARABLE
    reasons = "\n".join(result.reasons)
    assert "CVE-2025-53355.json" in reasons
    assert "budget" in reasons
    assert "delete evals/baselines/cve/" in reasons


def test_a_gated_incomplete_target_is_not_comparable():
    result = judge([given.a_comparison(TargetOutcome.INCOMPLETE)], [])

    assert result.verdict == CVEGateVerdict.NOT_COMPARABLE
    assert any(given.CVE_ID in reason for reason in result.reasons)


def test_an_undecided_replay_is_not_comparable():
    pending = given.a_comparison(TargetOutcome.PENDING_REPLAY)
    undecided = settle(pending, [True, True], ReplayRule())

    result = judge([undecided], [])

    assert result.verdict == CVEGateVerdict.NOT_COMPARABLE
    assert any(given.CVE_ID in reason for reason in result.reasons)


def test_an_ungated_incomplete_target_leaves_the_run_comparable():
    baseline = given.a_confirmed_baseline([DETECTED] * 5 + [MISSED])
    comparison = compare_target(baseline, given.a_candidate([DETECTED], completed=False))

    assert judge([comparison], []).verdict == CVEGateVerdict.GREEN


def test_a_regression_is_red_and_named():
    comparisons = [
        given.a_comparison(TargetOutcome.HELD, cve_id="CVE-2025-53109"),
        given.a_comparison(TargetOutcome.REGRESSION),
    ]

    result = judge(comparisons, [])

    assert result.verdict == CVEGateVerdict.RED
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
        given.a_comparison(outcome, cve_id=f"CVE-2025-{index}")
        for index, outcome in enumerate(outcomes)
    ]

    assert judge(comparisons, []).verdict == CVEGateVerdict.GREEN


@pytest.mark.parametrize(
    ("verdict", "code"),
    [(CVEGateVerdict.GREEN, 0), (CVEGateVerdict.RED, 1), (CVEGateVerdict.NOT_COMPARABLE, 3)],
)
def test_exit_code(verdict: CVEGateVerdict, code: int):
    assert exit_code(verdict) == code
