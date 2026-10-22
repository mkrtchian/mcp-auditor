"""Whether a recording of one acceptance server is written, and as what (ADR 023, ADR 024), the
mirror of `cve_recording` with an alarm in place of a miss."""

from collections.abc import Mapping

from pydantic import BaseModel

from evals.baseline import BaselineStatus, RecordingRef
from evals.gate import ReplayRule
from evals.nuisance_gate import ServerComparison, ServerOutcome
from evals.nuisance_gate_baseline import (
    WHOLE_RESET,
    NuisanceGateConditions,
    NuisanceServerBaseline,
    condition_mismatches,
    server_reset,
)
from evals.recording import RecordingRefused

_FAILED_RUN = "a run did not complete: a baseline holds every run its conditions claim"
# INCONCLUSIVE has no CVE counterpart: a server already unstable stays recordable over.
_GREEN = {
    ServerOutcome.HELD,
    ServerOutcome.NOT_GATED,
    ServerOutcome.INCONCLUSIVE,
    ServerOutcome.ALARM_NOT_REPRODUCED,
}


class ServerRecording(BaseModel):
    server_package: str
    conditions: NuisanceGateConditions
    fixture_fingerprint: str
    commit: str
    recorded_at: str
    runs: list[bool]
    completed: bool
    image_ids: dict[str, str]


def decide_recording(
    existing: NuisanceServerBaseline | None,
    recording: ServerRecording,
    comparison: ServerComparison | None,
) -> NuisanceServerBaseline | RecordingRefused:
    if not recording.completed:
        return RecordingRefused(reasons=[_FAILED_RUN])
    if existing is None:
        return _baseline_from(recording, BaselineStatus.EXPLORATORY, ReplayRule())
    if existing.status == BaselineStatus.EXPLORATORY:
        return _confirmation(existing, recording)
    return _replacement(existing, recording, comparison)


def leaves_gated_set(
    existing: NuisanceServerBaseline | None, written: NuisanceServerBaseline
) -> bool:
    """Not a refusal: the session names it (ADR 024)."""
    return existing is not None and existing.gated() and not written.gated()


def decide_recordings(
    decisions: Mapping[str, NuisanceServerBaseline | RecordingRefused],
) -> list[NuisanceServerBaseline] | RecordingRefused:
    """All or none, so a run is never half recorded."""
    reasons = [
        f"{package}: {reason}"
        for package, decision in decisions.items()
        if isinstance(decision, RecordingRefused)
        for reason in decision.reasons
    ]
    if reasons:
        return RecordingRefused(reasons=reasons)
    return [
        decision for decision in decisions.values() if isinstance(decision, NuisanceServerBaseline)
    ]


def _confirmation(
    existing: NuisanceServerBaseline, recording: ServerRecording
) -> NuisanceServerBaseline | RecordingRefused:
    """The second recording adds its runs after the first's (ADR 023)."""
    differences = _differences(existing, recording)
    if existing.commit != recording.commit:
        differences.append(f"it was recorded at {existing.commit}, this run at {recording.commit}")
    if differences:
        return RecordingRefused(
            reasons=[
                f"the exploratory baseline differs from this recording ({'; '.join(differences)}): "
                "confirm it at its own commit, or delete it in a commit of its own (ADR 020)"
            ]
        )
    confirmed = _baseline_from(recording, BaselineStatus.CONFIRMED, existing.replay_rule)
    return confirmed.model_copy(
        update={"runs": existing.runs + recording.runs, "confirms": _ref(existing)}
    )


def _replacement(
    existing: NuisanceServerBaseline,
    recording: ServerRecording,
    comparison: ServerComparison | None,
) -> NuisanceServerBaseline | RecordingRefused:
    reasons = _reset_refusals(existing, recording) or _comparison_refusals(comparison)
    if reasons:
        return RecordingRefused(reasons=reasons)
    replacing = _baseline_from(recording, BaselineStatus.CONFIRMED, existing.replay_rule)
    return replacing.model_copy(update={"replaces": _ref(existing)})


def _reset_refusals(existing: NuisanceServerBaseline, recording: ServerRecording) -> list[str]:
    """A reset starts from a deleted file, so a confirmed one is never recorded over it."""
    reasons: list[str] = []
    if existing.fixture_fingerprint != recording.fixture_fingerprint:
        reasons.append(server_reset(recording.server_package))
    mismatches = condition_mismatches({existing.server_package: existing}, recording.conditions)
    if mismatches:
        reasons += [*mismatches, WHOLE_RESET]
    return reasons


def _comparison_refusals(comparison: ServerComparison | None) -> list[str]:
    if comparison is not None and comparison.outcome in _GREEN:
        return []
    if comparison is not None and comparison.outcome == ServerOutcome.REGRESSION:
        return [
            "the gate found a regression on this server: a baseline is never recorded while "
            "the gate is red (ADR 016)"
        ]
    outcome = "no comparison" if comparison is None else comparison.outcome.value
    return [
        f"this server's comparison is {outcome}: a confirmed baseline is recorded over only "
        "when its server held, was not gated, was inconclusive, or its alarm did not reproduce"
    ]


def _differences(existing: NuisanceServerBaseline, recording: ServerRecording) -> list[str]:
    differences = condition_mismatches({existing.server_package: existing}, recording.conditions)
    if existing.fixture_fingerprint != recording.fixture_fingerprint:
        differences.append("its fixture changed")
    return differences


def _baseline_from(
    recording: ServerRecording, status: BaselineStatus, rule: ReplayRule
) -> NuisanceServerBaseline:
    return NuisanceServerBaseline(
        server_package=recording.server_package,
        status=status,
        conditions=recording.conditions,
        fixture_fingerprint=recording.fixture_fingerprint,
        replay_rule=rule,
        commit=recording.commit,
        recorded_at=recording.recorded_at,
        runs=recording.runs,
        image_ids=recording.image_ids,
    )


def _ref(baseline: NuisanceServerBaseline) -> RecordingRef:
    return RecordingRef(commit=baseline.commit, recorded_at=baseline.recorded_at)
