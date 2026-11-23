"""The baselines the two CVE benchmark gates keep, one file per target or server: the texts and
rules their gates and recordings share (ADR 016, ADR 020, ADR 023, ADR 024)."""

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from pydantic import BaseModel

from evals.baseline import BaselineStatus
from evals.eval_session import Refused
from evals.recording import RecordingRefused

RUN_NOT_COMPLETED = "a run did not complete: a baseline holds every run its conditions claim"
BASELINE_FILES_CHANGED = "the baseline files changed during the runs: record again"


def whole_reset(directory: str) -> str:
    return (
        f"Reset the whole baseline: delete {directory}/ in a commit of its own, "
        "then record twice at one commit (ADR 020)."
    )


def condition_mismatches_by_file(
    conditions_by_file: Mapping[str, BaseModel], candidate: BaseModel
) -> list[str]:
    """In the order of the mapping: each gate sorts its files its own way."""
    expected = candidate.model_dump()
    return [
        f"{file_name}: {field} is {recorded!r}, the run has {expected[field]!r}"
        for file_name, conditions in conditions_by_file.items()
        for field, recorded in conditions.model_dump().items()
        if recorded != expected[field]
    ]


def unconfirmed_baseline_detail(commit: str) -> str:
    return (
        f"unconfirmed baseline recorded at {commit}: confirm it with a second "
        "recording at that commit, or delete it in a commit of its own"
    )


def all_or_none[B](decisions: Mapping[str, B | RecordingRefused]) -> list[B] | RecordingRefused:
    """All or none, so a run is never half recorded."""
    reasons = [
        f"{key}: {reason}"
        for key, decision in decisions.items()
        if isinstance(decision, RecordingRefused)
        for reason in decision.reasons
    ]
    if reasons:
        return RecordingRefused(reasons=reasons)
    return [
        decision for decision in decisions.values() if not isinstance(decision, RecordingRefused)
    ]


class Gated(Protocol):
    def gated(self) -> bool: ...


def leaves_gated_set(existing: Gated | None, written: Gated) -> bool:
    """Not a refusal: the session names it (ADR 024)."""
    return existing is not None and existing.gated() and not written.gated()


def refused_confirmation(differences: list[str]) -> RecordingRefused:
    return RecordingRefused(
        reasons=[
            f"the unconfirmed baseline differs from this recording ({'; '.join(differences)}): "
            "confirm it at its own commit, or delete it in a commit of its own (ADR 020)"
        ]
    )


def red_gate_reason(noun: str) -> str:
    return (
        f"the gate found a regression on this {noun}: a baseline is never recorded while "
        "the gate is red (ADR 016)"
    )


def next_recording_step(status: BaselineStatus, command: str, directory: str) -> str:
    if status == BaselineStatus.CONFIRMED:
        return f"Commit {directory} by hand."
    return (
        f"Run {command} again now, at this commit and on these images, to confirm it. "
        f"Commit {directory} by hand once confirmed."
    )


@dataclass(frozen=True)
class BaselineStore[B]:
    load: Callable[[Path], dict[str, B]]
    integrity: Callable[[B], list[str]]


def load_checked[B](directory: Path, title: str, store: BaselineStore[B]) -> dict[str, B]:
    try:
        baselines = store.load(directory)
    except ValueError as error:
        raise Refused(title, [f"{directory} holds an invalid baseline file: {error}"]) from error
    problems = [problem for b in baselines.values() for problem in store.integrity(b)]
    if problems:
        raise Refused(title, problems)
    return baselines
