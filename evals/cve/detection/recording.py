"""Whether a recording of one target is written, and as what (ADR 023, ADR 024)."""

from collections.abc import Mapping

from pydantic import BaseModel

from evals.baseline import BaselineStatus, RecordingRef
from evals.cve.detection.baseline import DetectionBaseline, DetectionRunConditions
from evals.cve.detection.gate import (
    WHOLE_RESET,
    TargetComparison,
    TargetOutcome,
    condition_mismatches,
    target_reset,
)
from evals.cve_grammar import CVEStatus
from evals.gate import RetestRule
from evals.recording import RecordingRefused

_FAILED_RUN = "a run did not complete: a baseline holds every run its conditions claim"
_GREEN = {TargetOutcome.HELD, TargetOutcome.NOT_GATED, TargetOutcome.MISS_NOT_REPRODUCED}


class TargetRecording(BaseModel):
    flaw_id: str
    conditions: DetectionRunConditions
    fixture_fingerprint: str
    commit: str
    recorded_at: str
    runs: list[CVEStatus]
    completed: bool
    image_ids: dict[str, str]


def decide_recording(
    existing: DetectionBaseline | None,
    recording: TargetRecording,
    comparison: TargetComparison | None,
) -> DetectionBaseline | RecordingRefused:
    if not recording.completed:
        return RecordingRefused(reasons=[_FAILED_RUN])
    if existing is None:
        return _baseline_from(recording, BaselineStatus.UNCONFIRMED, RetestRule())
    if existing.status == BaselineStatus.UNCONFIRMED:
        return _confirmation(existing, recording)
    return _replacement(existing, recording, comparison)


def leaves_gated_set(existing: DetectionBaseline | None, written: DetectionBaseline) -> bool:
    """Not a refusal: the session names it (ADR 024)."""
    return existing is not None and existing.gated() and not written.gated()


def decide_recordings(
    decisions: Mapping[str, DetectionBaseline | RecordingRefused],
) -> list[DetectionBaseline] | RecordingRefused:
    """All or none, so a run is never half recorded."""
    reasons = [
        f"{flaw_id}: {reason}"
        for flaw_id, decision in decisions.items()
        if isinstance(decision, RecordingRefused)
        for reason in decision.reasons
    ]
    if reasons:
        return RecordingRefused(reasons=reasons)
    return [decision for decision in decisions.values() if isinstance(decision, DetectionBaseline)]


def _confirmation(
    existing: DetectionBaseline, recording: TargetRecording
) -> DetectionBaseline | RecordingRefused:
    """The second recording adds its runs after the first's (ADR 023)."""
    differences = _differences(existing, recording)
    if existing.commit != recording.commit:
        differences.append(f"it was recorded at {existing.commit}, this run at {recording.commit}")
    if differences:
        return RecordingRefused(
            reasons=[
                f"the unconfirmed baseline differs from this recording ({'; '.join(differences)}): "
                "confirm it at its own commit, or delete it in a commit of its own (ADR 020)"
            ]
        )
    confirmed = _baseline_from(recording, BaselineStatus.CONFIRMED, existing.retest_rule)
    return confirmed.model_copy(
        update={"runs": existing.runs + recording.runs, "confirms": _ref(existing)}
    )


def _replacement(
    existing: DetectionBaseline, recording: TargetRecording, comparison: TargetComparison | None
) -> DetectionBaseline | RecordingRefused:
    reasons = _reset_refusals(existing, recording) or _comparison_refusals(comparison)
    if reasons:
        return RecordingRefused(reasons=reasons)
    replacing = _baseline_from(recording, BaselineStatus.CONFIRMED, existing.retest_rule)
    return replacing.model_copy(update={"replaces": _ref(existing)})


def _reset_refusals(existing: DetectionBaseline, recording: TargetRecording) -> list[str]:
    """A reset starts from a deleted file, so a confirmed one is never recorded over it."""
    reasons: list[str] = []
    if existing.fixture_fingerprint != recording.fixture_fingerprint:
        reasons.append(target_reset(recording.flaw_id))
    mismatches = condition_mismatches({existing.flaw_id: existing}, recording.conditions)
    if mismatches:
        reasons += [*mismatches, WHOLE_RESET]
    return reasons


def _comparison_refusals(comparison: TargetComparison | None) -> list[str]:
    if comparison is not None and comparison.outcome in _GREEN:
        return []
    if comparison is not None and comparison.outcome == TargetOutcome.REGRESSION:
        return [
            "the gate found a regression on this target: a baseline is never recorded while "
            "the gate is red (ADR 016)"
        ]
    outcome = "no comparison" if comparison is None else comparison.outcome.value
    return [
        f"this target's comparison is {outcome}: a confirmed baseline is recorded over only "
        "when its target held, was not gated, or its miss did not reproduce"
    ]


def _differences(existing: DetectionBaseline, recording: TargetRecording) -> list[str]:
    differences = condition_mismatches({existing.flaw_id: existing}, recording.conditions)
    if existing.fixture_fingerprint != recording.fixture_fingerprint:
        differences.append("its fixture changed")
    return differences


def _baseline_from(
    recording: TargetRecording, status: BaselineStatus, rule: RetestRule
) -> DetectionBaseline:
    return DetectionBaseline(
        flaw_id=recording.flaw_id,
        status=status,
        conditions=recording.conditions,
        fixture_fingerprint=recording.fixture_fingerprint,
        retest_rule=rule,
        commit=recording.commit,
        recorded_at=recording.recorded_at,
        runs=recording.runs,
        image_ids=recording.image_ids,
    )


def _ref(baseline: DetectionBaseline) -> RecordingRef:
    return RecordingRef(commit=baseline.commit, recorded_at=baseline.recorded_at)
