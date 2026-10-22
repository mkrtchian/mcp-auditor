import pytest

import tests.unit.support.test_nuisance_gate_recording_given as given
from evals.baseline import BaselineStatus, RecordingRef
from evals.gate import ReplayRule
from evals.nuisance_gate import ServerOutcome
from evals.nuisance_gate_baseline import NuisanceServerBaseline
from evals.nuisance_gate_recording import (
    ServerRecording,
    decide_recording,
    decide_recordings,
    leaves_gated_set,
)
from evals.recording import RecordingRefused


def test_an_incomplete_recording_is_refused():
    decision = decide_recording(None, given.a_recording(completed=False), None)

    assert isinstance(decision, RecordingRefused)
    assert "every run its conditions claim" in decision.reasons[0]


def test_no_file_gives_an_exploratory_baseline_of_the_recording():
    recording = given.a_recording([False, True, False])

    decision = decide_recording(None, recording, None)

    assert decision == NuisanceServerBaseline(
        server_package=recording.server_package,
        status=BaselineStatus.EXPLORATORY,
        conditions=recording.conditions,
        fixture_fingerprint=recording.fixture_fingerprint,
        replay_rule=ReplayRule(),
        commit=recording.commit,
        recorded_at=recording.recorded_at,
        runs=recording.runs,
        image_ids=recording.image_ids,
    )


def test_an_exploratory_file_is_confirmed_at_its_own_commit_with_both_recordings_runs():
    existing = given.an_exploratory_baseline([False] * 3)
    recording = given.a_recording([True, False, False])

    decision = decide_recording(existing, recording, given.a_comparison(ServerOutcome.NOT_GATED))

    assert isinstance(decision, NuisanceServerBaseline)
    assert decision.status == BaselineStatus.CONFIRMED
    assert decision.runs == [False, False, False, True, False, False]
    assert decision.confirms == RecordingRef(
        commit=existing.commit, recorded_at=existing.recorded_at
    )
    assert decision.recorded_at == recording.recorded_at


@pytest.mark.parametrize(
    ("recording", "difference"),
    [
        (given.a_recording(commit="fedcba9"), "recorded at 0123abc, this run at fedcba9"),
        (given.a_recording(fixture="another"), "its fixture changed"),
        (given.a_recording(recording_conditions=given.conditions(runs=1)), "runs is 3"),
    ],
    ids=["other commit", "other fixture", "other conditions"],
)
def test_an_exploratory_file_differing_from_the_recording_is_refused_naming_the_difference(
    recording: ServerRecording, difference: str
):
    decision = decide_recording(
        given.an_exploratory_baseline(), recording, given.a_comparison(ServerOutcome.NOT_GATED)
    )

    assert isinstance(decision, RecordingRefused)
    assert difference in decision.reasons[0]
    assert "confirm it at its own commit" in decision.reasons[0]
    assert "delete it in a commit of its own" in decision.reasons[0]


@pytest.mark.parametrize(
    "outcome",
    [
        ServerOutcome.HELD,
        ServerOutcome.NOT_GATED,
        ServerOutcome.INCONCLUSIVE,
        ServerOutcome.ALARM_NOT_REPRODUCED,
    ],
)
def test_a_confirmed_file_is_replaced_from_a_green_comparison(outcome: ServerOutcome):
    existing = given.a_gated_baseline()
    recording = given.a_recording([False] * 3, commit="fedcba9")

    decision = decide_recording(existing, recording, given.a_comparison(outcome))

    assert isinstance(decision, NuisanceServerBaseline)
    assert decision.status == BaselineStatus.CONFIRMED
    assert decision.runs == recording.runs
    assert decision.confirms is None
    assert decision.replaces == RecordingRef(
        commit=existing.commit, recorded_at=existing.recorded_at
    )


def test_a_confirmed_file_is_not_recorded_over_a_regression():
    decision = decide_recording(
        given.a_gated_baseline(),
        given.a_recording(),
        given.a_comparison(ServerOutcome.REGRESSION),
    )

    assert isinstance(decision, RecordingRefused)
    assert any("ADR 016" in reason for reason in decision.reasons)


@pytest.mark.parametrize("outcome", [ServerOutcome.PENDING_REPLAY, ServerOutcome.INCOMPLETE, None])
def test_a_confirmed_file_is_not_recorded_over_an_unsettled_comparison(
    outcome: ServerOutcome | None,
):
    comparison = None if outcome is None else given.a_comparison(outcome)

    decision = decide_recording(given.a_gated_baseline(), given.a_recording(), comparison)

    assert isinstance(decision, RecordingRefused)


@pytest.mark.parametrize(
    ("recording", "outcome", "reset"),
    [
        (
            given.a_recording(fixture="another"),
            ServerOutcome.FIXTURE_CHANGED,
            "with --server npm:@modelcontextprotocol/server-filesystem",
        ),
        (
            given.a_recording(recording_conditions=given.conditions(runs=1)),
            ServerOutcome.HELD,
            "delete evals/baselines/nuisance/ in a commit of its own",
        ),
    ],
    ids=["changed fixture", "changed conditions"],
)
def test_a_confirmed_file_with_a_changed_fixture_or_conditions_needs_a_reset(
    recording: ServerRecording, outcome: ServerOutcome, reset: str
):
    decision = decide_recording(given.a_gated_baseline(), recording, given.a_comparison(outcome))

    assert isinstance(decision, RecordingRefused)
    assert any(reset in reason for reason in decision.reasons)


def test_a_recording_that_takes_a_gated_server_out_of_the_gated_set_is_written_and_named():
    existing = given.a_gated_baseline()

    written = decide_recording(
        existing,
        given.a_recording([True, False, False]),
        given.a_comparison(ServerOutcome.ALARM_NOT_REPRODUCED),
    )

    assert isinstance(written, NuisanceServerBaseline)
    assert leaves_gated_set(existing, written)


def test_a_recording_that_keeps_a_gated_server_gated_does_not_leave_the_gated_set():
    existing = given.a_gated_baseline()

    written = decide_recording(
        existing, given.a_recording([False] * 3), given.a_comparison(ServerOutcome.HELD)
    )

    assert isinstance(written, NuisanceServerBaseline)
    assert not leaves_gated_set(existing, written)


def test_every_decided_server_is_written_when_none_is_refused():
    first = given.an_exploratory_baseline(package="npm:first")
    second = given.an_exploratory_baseline(package="npm:second")

    decision = decide_recordings({"npm:first": first, "npm:second": second})

    assert decision == [first, second]


def test_one_refused_server_means_no_baseline_to_write():
    written = given.an_exploratory_baseline(package="npm:first")
    refused = RecordingRefused(reasons=["the gate saw a regression"])

    decision = decide_recordings({"npm:first": written, "npm:second": refused})

    assert decision == RecordingRefused(reasons=["npm:second: the gate saw a regression"])
