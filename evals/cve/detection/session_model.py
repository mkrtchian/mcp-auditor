"""The value objects of one gated detection suite run: its options, its injected harness, the
audits it produces and the session fixed before any audit."""

from collections.abc import Awaitable, Callable, Sequence
from dataclasses import dataclass
from pathlib import Path

from evals.cve.detection.baseline import DetectionBaseline, DetectionRunConditions
from evals.cve.detection.replay import ReplayAttemptFailure, UncheckedReason
from evals.cve.detection.targets import ACCEPTANCE_TARGETS, Target
from evals.cve.grammar import RunGrade
from evals.cve.places import Places
from evals.cve.server_health import NO_INCIDENTS, ServerHealth
from evals.eval_session import TreeState
from mcp_auditor.domain.models import AuditReport


@dataclass(frozen=True)
class GradedAudit:
    grade: RunGrade
    report: AuditReport
    health: ServerHealth = NO_INCIDENTS
    unchecked_reason: UncheckedReason | None = None  # set on a replay left unchecked
    replay_attempt_failures: tuple[ReplayAttemptFailure, ...] = ()


type AuditTarget = Callable[[Target], Awaitable[GradedAudit | None]]
"""One audit of one target, None when it did not complete (launch or infra failure). The
session may call it concurrently: it decides itself how many audits run at once."""

type CheckTarget = Callable[[Target], Awaitable[list[str]]]
"""The no-LLM pre-run check of one target: its out-of-calibration reasons, empty when it is
live and fixed. The session gathers it over every target before any audit. A configuration error
it raises (an unknown kept id, a planting_spec refusal) is not an out-of-calibration reason: it
propagates and crashes the run before any audit. The session calls it concurrently, like the
audit."""

type Baselines = dict[str, DetectionBaseline]


@dataclass(frozen=True)
class DetectionOptions:
    targets: list[Target]  # already filtered by --flaw
    conditions: DetectionRunConditions
    no_baseline: bool
    record_baseline: bool


@dataclass(frozen=True)
class DetectionHarness:
    audit: AuditTarget
    check: CheckTarget  # the pre-run check, gathered over every target before any audit
    announce_audits: Callable[[int], None]  # the main audits about to run, once checked
    baselines: Path
    read_tree: Callable[[], TreeState]
    image_ids: Callable[[Sequence[str]], dict[str, str]]
    clock: Callable[[], str]  # ISO timestamp for recorded_at
    places: Places  # loaded once by the composition root, read by the fixture fingerprint


@dataclass(frozen=True)
class DetectionAudit:
    flaw_id: str
    run_index: int  # within its target, in submission order
    report: AuditReport


@dataclass(frozen=True)
class TargetRuns:
    target: Target
    grades: list[RunGrade]
    completed: bool
    audits: list[DetectionAudit]


@dataclass(frozen=True)
class GatedSession:
    """Fixed before any audit. `tree` is set exactly when the run records."""

    options: DetectionOptions
    harness: DetectionHarness
    files: Baselines  # every file read at start, orphans included
    tree: TreeState | None

    def baselines(self) -> Baselines:
        return {flaw_id: b for flaw_id, b in self.files.items() if flaw_id in _BENCHMARKED}

    def orphans(self) -> list[str]:
        return [f"{flaw_id}.json" for flaw_id in sorted(self.files) if flaw_id not in _BENCHMARKED]


_BENCHMARKED = frozenset(target.flaw_id for target in ACCEPTANCE_TARGETS)
