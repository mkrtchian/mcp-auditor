"""Whether a recording of one nuisance acceptance server is written, and as what (ADR 023, ADR
024), the mirror of `evals.cve.detection.recording` with an alarm in place of a miss."""

from pydantic import BaseModel

from evals.baseline import BaselineStatus, RecordingRef
from evals.cve.file_baselines import RUN_NOT_COMPLETED, red_gate_reason, refused_confirmation
from evals.cve.nuisance.gate.gate import ServerComparison, ServerOutcome
from evals.cve.nuisance.gate.gate_baseline import (
    WHOLE_RESET,
    NuisanceGateConditions,
    NuisanceServerBaseline,
    condition_mismatches,
    server_reset,
)
from evals.gate import RetestRule
from evals.recording import RecordingRefused

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
        return RecordingRefused(reasons=[RUN_NOT_COMPLETED])
    if existing is None:
        return _baseline_from(recording, BaselineStatus.UNCONFIRMED, RetestRule())
    if existing.status == BaselineStatus.UNCONFIRMED:
        return _confirmation(existing, recording)
    return _replacement(existing, recording, comparison)


def _confirmation(
    existing: NuisanceServerBaseline, recording: ServerRecording
) -> NuisanceServerBaseline | RecordingRefused:
    """The second recording adds its runs after the first's (ADR 023)."""
    differences = _differences(existing, recording)
    if existing.commit != recording.commit:
        differences.append(f"it was recorded at {existing.commit}, this run at {recording.commit}")
    if differences:
        return refused_confirmation(differences)
    confirmed = _baseline_from(recording, BaselineStatus.CONFIRMED, existing.retest_rule)
    return confirmed.model_copy(
        update={"runs": existing.runs + recording.runs, "confirms": RecordingRef.of(existing)}
    )


def _replacement(
    existing: NuisanceServerBaseline,
    recording: ServerRecording,
    comparison: ServerComparison | None,
) -> NuisanceServerBaseline | RecordingRefused:
    reasons = _reset_refusals(existing, recording) or _comparison_refusals(comparison)
    if reasons:
        return RecordingRefused(reasons=reasons)
    replacing = _baseline_from(recording, BaselineStatus.CONFIRMED, existing.retest_rule)
    return replacing.model_copy(update={"replaces": RecordingRef.of(existing)})


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
        return [red_gate_reason("server")]
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
    recording: ServerRecording, status: BaselineStatus, rule: RetestRule
) -> NuisanceServerBaseline:
    return NuisanceServerBaseline(
        server_package=recording.server_package,
        status=status,
        conditions=recording.conditions,
        fixture_fingerprint=recording.fixture_fingerprint,
        retest_rule=rule,
        commit=recording.commit,
        recorded_at=recording.recorded_at,
        runs=recording.runs,
        image_ids=recording.image_ids,
    )
