import pytest

import tests.unit.support.test_cve_recording_given as given
from evals.baseline import BaselineStatus, RecordingRef
from evals.cve_baseline import CVETargetBaseline
from evals.cve_gate import TargetOutcome
from evals.cve_recording import (
    TargetRecording,
    decide_recording,
    decide_recordings,
    leaves_gated_set,
)
from evals.gate import ReplayRule
from evals.recording import RecordingRefused

DETECTED = given.DETECTED
MISSED = given.MISSED


def test_an_incomplete_recording_is_refused():
    decision = decide_recording(None, given.a_recording(completed=False), None)

    assert isinstance(decision, RecordingRefused)
    assert "every run its conditions claim" in decision.reasons[0]


def test_no_file_gives_an_exploratory_baseline_of_the_recording():
    recording = given.a_recording()

    decision = decide_recording(None, recording, None)

    assert decision == CVETargetBaseline(
        cve_id=recording.cve_id,
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
    existing = given.an_exploratory_baseline([DETECTED] * 3)
    recording = given.a_recording([MISSED, DETECTED, DETECTED])

    decision = decide_recording(existing, recording, given.a_comparison(TargetOutcome.NOT_GATED))

    assert isinstance(decision, CVETargetBaseline)
    assert decision.status == BaselineStatus.CONFIRMED
    assert decision.runs == [DETECTED, DETECTED, DETECTED, MISSED, DETECTED, DETECTED]
    assert decision.confirms == RecordingRef(
        commit=existing.commit, recorded_at=existing.recorded_at
    )
    assert decision.recorded_at == recording.recorded_at


def test_an_exploratory_file_at_another_commit_is_refused_with_the_procedure():
    decision = decide_recording(
        given.an_exploratory_baseline(),
        given.a_recording(commit="fedcba9"),
        given.a_comparison(TargetOutcome.NOT_GATED),
    )

    assert isinstance(decision, RecordingRefused)
    assert _names_the_exploratory_procedure(decision)


@pytest.mark.parametrize(
    "recording",
    [
        given.a_recording(recording_conditions=given.conditions(budget=20)),
        given.a_recording(fixture="another"),
    ],
    ids=["other conditions", "other fixture"],
)
def test_an_exploratory_file_under_other_conditions_or_fixture_is_refused(
    recording: TargetRecording,
):
    decision = decide_recording(
        given.an_exploratory_baseline(), recording, given.a_comparison(TargetOutcome.NOT_GATED)
    )

    assert isinstance(decision, RecordingRefused)
    assert _names_the_exploratory_procedure(decision)


@pytest.mark.parametrize(
    "outcome",
    [TargetOutcome.HELD, TargetOutcome.NOT_GATED, TargetOutcome.MISS_NOT_REPRODUCED],
)
def test_a_confirmed_file_is_replaced_from_a_green_comparison(outcome: TargetOutcome):
    existing = given.a_gated_baseline()
    recording = given.a_recording([DETECTED] * 3, commit="fedcba9")

    decision = decide_recording(existing, recording, given.a_comparison(outcome))

    assert isinstance(decision, CVETargetBaseline)
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
        given.a_comparison(TargetOutcome.REGRESSION),
    )

    assert isinstance(decision, RecordingRefused)
    assert any("ADR 016" in reason for reason in decision.reasons)


@pytest.mark.parametrize(
    ("recording", "outcome"),
    [
        (given.a_recording(fixture="another"), TargetOutcome.FIXTURE_CHANGED),
        (given.a_recording(recording_conditions=given.conditions(budget=20)), TargetOutcome.HELD),
    ],
    ids=["changed fixture", "changed conditions"],
)
def test_a_confirmed_file_with_a_changed_fixture_or_conditions_needs_a_reset(
    recording: TargetRecording, outcome: TargetOutcome
):
    decision = decide_recording(given.a_gated_baseline(), recording, given.a_comparison(outcome))

    assert isinstance(decision, RecordingRefused)
    assert any("delete evals/baselines/cve/" in reason for reason in decision.reasons)


def test_a_recording_that_takes_a_gated_target_out_of_the_gated_set_is_written_and_named():
    existing = given.a_gated_baseline()

    written = decide_recording(
        existing,
        given.a_recording([MISSED, DETECTED, DETECTED]),
        given.a_comparison(TargetOutcome.MISS_NOT_REPRODUCED),
    )

    assert isinstance(written, CVETargetBaseline)
    assert leaves_gated_set(existing, written)


def test_a_recording_that_keeps_a_gated_target_gated_does_not_leave_the_gated_set():
    existing = given.a_gated_baseline()

    written = decide_recording(
        existing, given.a_recording([DETECTED] * 3), given.a_comparison(TargetOutcome.HELD)
    )

    assert isinstance(written, CVETargetBaseline)
    assert not leaves_gated_set(existing, written)


def test_every_decided_target_is_written_when_none_is_refused():
    first = given.an_exploratory_baseline(cve_id="CVE-2025-53109")
    second = given.an_exploratory_baseline(cve_id="CVE-2025-53110")

    decision = decide_recordings({first.cve_id: first, second.cve_id: second})

    assert decision == [first, second]


def test_one_refused_target_means_no_baseline_to_write():
    written = given.an_exploratory_baseline(cve_id="CVE-2025-53109")
    refused = RecordingRefused(reasons=["the gate saw a regression"])

    decision = decide_recordings({written.cve_id: written, "CVE-2025-53110": refused})

    assert decision == RecordingRefused(reasons=["CVE-2025-53110: the gate saw a regression"])


def _names_the_exploratory_procedure(refused: RecordingRefused) -> bool:
    return any(
        "confirm it at its own commit" in reason and "delete it in a commit of its own" in reason
        for reason in refused.reasons
    )
