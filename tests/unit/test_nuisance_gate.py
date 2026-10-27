import pytest

import tests.unit.support.test_nuisance_gate_given as given
from evals.gate import ReplayRule
from evals.gate_verdict import GateVerdict
from evals.nuisance_gate import ServerOutcome, compare_server, exit_code, judge, settle
from evals.nuisance_gate_baseline import WHOLE_RESET, NuisanceServerBaseline

CLEAN = [False] * 3
ONE_ALARM = [False, True, False]


def test_a_server_without_a_file_has_no_baseline():
    comparison = compare_server(None, given.a_candidate(CLEAN))

    assert comparison.outcome == ServerOutcome.NO_BASELINE


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


def test_an_incomplete_candidate_on_a_gated_server():
    comparison = compare_server(
        given.a_gated_baseline(), given.a_candidate([False], completed=False)
    )

    assert comparison.outcome == ServerOutcome.INCOMPLETE


@pytest.mark.parametrize(
    ("runs", "outcome"),
    [(CLEAN, ServerOutcome.HELD), (ONE_ALARM, ServerOutcome.PENDING_REPLAY)],
    ids=["clean", "one alarm"],
)
def test_a_gated_server(runs: list[bool], outcome: ServerOutcome):
    comparison = compare_server(given.a_gated_baseline(), given.a_candidate(runs))

    assert comparison.outcome == outcome


@pytest.mark.parametrize(
    ("baseline", "runs", "outcome"),
    [
        (given.a_gated_baseline(), CLEAN, ServerOutcome.HELD),
        (given.a_gated_baseline(), ONE_ALARM, ServerOutcome.PENDING_REPLAY),
        (given.a_confirmed_baseline([False] * 5 + [True]), CLEAN, ServerOutcome.NOT_GATED),
        (given.an_exploratory_baseline(), ONE_ALARM, ServerOutcome.NOT_GATED),
    ],
    ids=["held", "pending", "flagged baseline", "exploratory"],
)
def test_a_comparison_carries_the_baseline_runs(
    baseline: NuisanceServerBaseline, runs: list[bool], outcome: ServerOutcome
):
    comparison = compare_server(baseline, given.a_candidate(runs))

    assert comparison.outcome == outcome
    assert comparison.baseline_runs == baseline.runs


def test_a_comparison_without_a_baseline_carries_no_baseline_runs():
    comparison = compare_server(None, given.a_candidate(CLEAN))

    assert comparison.baseline_runs == []


def test_settle_keeps_the_baseline_runs():
    pending = compare_server(given.a_gated_baseline(), given.a_candidate(ONE_ALARM))

    settled = settle(pending, [True] * 4, ReplayRule())

    assert settled.outcome == ServerOutcome.REGRESSION
    assert settled.baseline_runs == [False] * 6


def test_an_alarm_reproduced_four_times_is_a_regression():
    pending = given.a_comparison(ServerOutcome.PENDING_REPLAY)
    replays: list[bool | None] = [False, True, True, True, True]

    settled = settle(pending, replays, ReplayRule())

    assert settled.outcome == ServerOutcome.REGRESSION
    assert settled.replays == [False, True, True, True, True]


def test_an_alarm_cleared_by_its_replays_is_not_reproduced():
    pending = given.a_comparison(ServerOutcome.PENDING_REPLAY)

    settled = settle(pending, [False, False], ReplayRule())

    assert settled.outcome == ServerOutcome.ALARM_NOT_REPRODUCED


def test_an_undecided_replay_keeps_the_alarm_pending():
    pending = given.a_comparison(ServerOutcome.PENDING_REPLAY)

    settled = settle(pending, [True], ReplayRule())

    assert settled.outcome == ServerOutcome.PENDING_REPLAY
    assert settled.replays == [True]


def test_a_replay_that_did_not_complete_leaves_the_server_incomplete():
    pending = given.a_comparison(ServerOutcome.PENDING_REPLAY)

    settled = settle(pending, [True, None], ReplayRule())

    assert settled.outcome == ServerOutcome.INCOMPLETE
    assert settled.replays == [True]


def test_a_condition_mismatch_is_not_comparable_with_the_whole_reset():
    result = judge([given.a_comparison(ServerOutcome.HELD)], ["a.json: runs is 3, the run has 1"])

    assert result.verdict == GateVerdict.NOT_COMPARABLE
    assert result.reasons == ["a.json: runs is 3, the run has 1", WHOLE_RESET]


@pytest.mark.parametrize(
    "outcome", [ServerOutcome.NOT_RUN, ServerOutcome.INCOMPLETE, ServerOutcome.PENDING_REPLAY]
)
def test_a_server_that_says_nothing_either_way_is_not_comparable(outcome: ServerOutcome):
    result = judge(
        [given.a_comparison(ServerOutcome.HELD, "npm:other"), given.a_comparison(outcome)], []
    )

    assert result.verdict == GateVerdict.NOT_COMPARABLE
    assert len(result.reasons) == 1
    assert result.reasons[0].startswith(f"{given.SERVER_PACKAGE}: {outcome.value}")


def test_a_regression_turns_the_gate_red():
    comparisons = [
        given.a_comparison(ServerOutcome.HELD, "npm:other"),
        given.a_comparison(ServerOutcome.REGRESSION),
    ]

    result = judge(comparisons, [])

    assert result.verdict == GateVerdict.RED
    assert len(result.reasons) == 1
    assert result.reasons[0].startswith(given.SERVER_PACKAGE)


def test_an_inconclusive_server_does_not_block_green_and_is_named():
    comparisons = [
        given.a_comparison(ServerOutcome.HELD, "npm:other"),
        given.a_comparison(ServerOutcome.INCONCLUSIVE),
    ]

    result = judge(comparisons, [])

    assert result.verdict == GateVerdict.GREEN
    assert len(result.reasons) == 1
    assert result.reasons[0].startswith(given.SERVER_PACKAGE)


def test_a_gate_with_no_gated_server_says_so():
    comparisons = [
        given.a_comparison(ServerOutcome.NO_BASELINE, "npm:other"),
        given.a_comparison(ServerOutcome.NOT_GATED),
    ]

    result = judge(comparisons, [])

    assert result.verdict == GateVerdict.GREEN
    assert result.reasons == ["no server is gated"]


@pytest.mark.parametrize(
    ("verdict", "code"),
    [(GateVerdict.GREEN, 0), (GateVerdict.RED, 1), (GateVerdict.NOT_COMPARABLE, 3)],
)
def test_exit_code(verdict: GateVerdict, code: int):
    assert exit_code(verdict) == code
