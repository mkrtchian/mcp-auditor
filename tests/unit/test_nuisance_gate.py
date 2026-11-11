import pytest

import tests.unit.support.test_nuisance_gate_given as given
from evals.cve.nuisance.gate import ServerOutcome, apply_retests, compare_server, decide
from evals.cve.nuisance.gate_baseline import WHOLE_RESET
from evals.gate import RetestRule
from evals.gate_outcome import GateOutcome

CLEAN = [False] * 3
ONE_ALARM = [False, True, False]


def test_a_server_without_a_file_has_no_baseline():
    comparison = compare_server(None, given.a_candidate(CLEAN))

    assert comparison.outcome == ServerOutcome.NO_BASELINE
    assert comparison.baseline_runs == []


def test_a_changed_fixture_leaves_the_comparison_with_the_server_reset():
    comparison = compare_server(
        given.a_gated_baseline(), given.a_candidate(CLEAN, fixture="another")
    )

    assert comparison.outcome == ServerOutcome.FIXTURE_CHANGED
    assert comparison.detail is not None
    assert (
        "delete evals/baselines/nuisance/npm__modelcontextprotocol_server-filesystem.json"
        in comparison.detail
    )
    assert f"--server {given.SERVER_PACKAGE}" in comparison.detail


def test_an_exploratory_file_does_not_gate_and_asks_to_be_confirmed_or_deleted():
    comparison = compare_server(given.an_exploratory_baseline(), given.a_candidate(ONE_ALARM))

    assert comparison.outcome == ServerOutcome.NOT_GATED
    assert comparison.detail is not None
    assert given.RECORDED_COMMIT in comparison.detail
    assert "confirm it" in comparison.detail
    assert "delete it" in comparison.detail


@pytest.mark.parametrize(
    ("runs", "outcome"),
    [(ONE_ALARM, ServerOutcome.INCONCLUSIVE), (CLEAN, ServerOutcome.NOT_GATED)],
    ids=["candidate alarm", "clean candidate"],
)
def test_a_server_flagged_in_its_baseline_is_unstable(runs: list[bool], outcome: ServerOutcome):
    baseline = given.a_confirmed_baseline([False] * 5 + [True])

    comparison = compare_server(baseline, given.a_candidate(runs))

    assert comparison.outcome == outcome
    assert comparison.detail == "flagged in 1 of 6 baseline runs"
    assert comparison.baseline_runs == baseline.runs


def test_an_incomplete_candidate_on_a_gated_server():
    comparison = compare_server(
        given.a_gated_baseline(), given.a_candidate([False], completed=False)
    )

    assert comparison.outcome == ServerOutcome.INCOMPLETE


@pytest.mark.parametrize(
    ("runs", "outcome"),
    [(CLEAN, ServerOutcome.HELD), (ONE_ALARM, ServerOutcome.PENDING_RETEST)],
    ids=["clean", "one alarm"],
)
def test_a_gated_server(runs: list[bool], outcome: ServerOutcome):
    comparison = compare_server(given.a_gated_baseline(), given.a_candidate(runs))

    assert comparison.outcome == outcome


def test_settle_keeps_the_baseline_runs():
    pending = compare_server(given.a_gated_baseline(), given.a_candidate(ONE_ALARM))

    settled = apply_retests(pending, [True] * 4, RetestRule())

    assert settled.outcome == ServerOutcome.REGRESSION
    assert settled.baseline_runs == [False] * 6


def test_an_alarm_reproduced_four_times_is_a_regression():
    pending = given.a_comparison(ServerOutcome.PENDING_RETEST)
    retests: list[bool | None] = [False, True, True, True, True]

    settled = apply_retests(pending, retests, RetestRule())

    assert settled.outcome == ServerOutcome.REGRESSION
    assert settled.retests == [False, True, True, True, True]


def test_an_alarm_cleared_by_its_replays_is_not_reproduced():
    pending = given.a_comparison(ServerOutcome.PENDING_RETEST)

    settled = apply_retests(pending, [False, False], RetestRule())

    assert settled.outcome == ServerOutcome.ALARM_NOT_REPRODUCED


def test_an_undecided_replay_keeps_the_alarm_pending():
    pending = given.a_comparison(ServerOutcome.PENDING_RETEST)

    settled = apply_retests(pending, [True], RetestRule())

    assert settled.outcome == ServerOutcome.PENDING_RETEST
    assert settled.retests == [True]


def test_a_replay_that_did_not_complete_leaves_the_server_incomplete():
    pending = given.a_comparison(ServerOutcome.PENDING_RETEST)

    settled = apply_retests(pending, [True, None], RetestRule())

    assert settled.outcome == ServerOutcome.INCOMPLETE
    assert settled.retests == [True]


def test_a_condition_mismatch_is_not_comparable_with_the_whole_reset():
    result = decide([given.a_comparison(ServerOutcome.HELD)], ["a.json: runs is 3, the run has 1"])

    assert result.outcome == GateOutcome.NOT_COMPARABLE
    assert result.reasons == ["a.json: runs is 3, the run has 1", WHOLE_RESET]


@pytest.mark.parametrize(
    "outcome", [ServerOutcome.NOT_RUN, ServerOutcome.INCOMPLETE, ServerOutcome.PENDING_RETEST]
)
def test_a_server_that_says_nothing_either_way_is_not_comparable(outcome: ServerOutcome):
    result = decide(
        [given.a_comparison(ServerOutcome.HELD, "npm:other"), given.a_comparison(outcome)], []
    )

    assert result.outcome == GateOutcome.NOT_COMPARABLE
    assert len(result.reasons) == 1
    assert result.reasons[0].startswith(f"{given.SERVER_PACKAGE}: {outcome.value}")


def test_a_regression_turns_the_gate_red():
    comparisons = [
        given.a_comparison(ServerOutcome.HELD, "npm:other"),
        given.a_comparison(ServerOutcome.REGRESSION),
    ]

    result = decide(comparisons, [])

    assert result.outcome == GateOutcome.RED
    assert len(result.reasons) == 1
    assert result.reasons[0].startswith(given.SERVER_PACKAGE)


def test_an_inconclusive_server_does_not_block_green_and_is_named():
    comparisons = [
        given.a_comparison(ServerOutcome.HELD, "npm:other"),
        given.a_comparison(ServerOutcome.INCONCLUSIVE),
    ]

    result = decide(comparisons, [])

    assert result.outcome == GateOutcome.GREEN
    assert len(result.reasons) == 1
    assert result.reasons[0].startswith(given.SERVER_PACKAGE)


def test_a_gate_with_no_gated_server_says_so():
    comparisons = [
        given.a_comparison(ServerOutcome.NO_BASELINE, "npm:other"),
        given.a_comparison(ServerOutcome.NOT_GATED),
    ]

    result = decide(comparisons, [])

    assert result.outcome == GateOutcome.GREEN
    assert result.reasons == ["no server is gated"]


def test_a_gate_result_writes_its_outcome_and_retests_under_the_glossary_keys():
    pending = compare_server(given.a_gated_baseline(), given.a_candidate(ONE_ALARM))
    retested = apply_retests(pending, [True], RetestRule())

    dumped = decide([retested], []).model_dump(mode="json")

    assert dumped["outcome"] == "not_comparable"
    assert dumped["servers"][0]["outcome"] == "pending_retest"
    assert dumped["servers"][0]["retests"] == [True]
