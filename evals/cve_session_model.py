"""The value objects of one gated CVE benchmark run: its options, its injected harness, the
audits it produces and the session fixed before any audit."""

from collections.abc import Awaitable, Callable, Sequence
from dataclasses import dataclass
from pathlib import Path

from evals.cve_baseline import CVERunConditions, CVETargetBaseline
from evals.cve_grammar import RunGrade
from evals.cve_places import Places
from evals.cve_targets import CVE_TARGETS, CVETarget
from evals.eval_session import TreeState
from mcp_auditor.domain.models import AuditReport


@dataclass(frozen=True)
class GradedAudit:
    grade: RunGrade
    report: AuditReport


type AuditTarget = Callable[[CVETarget], Awaitable[GradedAudit | None]]
"""One audit of one target, None when it did not complete (launch or infra failure). The
session may call it concurrently: it decides itself how many audits run at once."""

type CheckTarget = Callable[[CVETarget], Awaitable[list[str]]]
"""The no-LLM pre-run check of one target: its dead conditions, empty when it is live. The
session gathers it over every target before any audit. A configuration error it raises (an
unknown kept id, a planting_spec refusal) is not a dead condition: it propagates and crashes
the run before any audit. The session calls it concurrently, like the audit."""

type Baselines = dict[str, CVETargetBaseline]


@dataclass(frozen=True)
class CVEOptions:
    targets: list[CVETarget]  # already filtered by --cve
    conditions: CVERunConditions
    ungated: bool
    record_baseline: bool


@dataclass(frozen=True)
class CVEHarness:
    audit: AuditTarget
    check: CheckTarget  # the pre-run check, gathered over every target before any audit
    announce_audits: Callable[[int], None]  # the main audits about to run, once checked
    baselines: Path
    read_tree: Callable[[], TreeState]
    image_ids: Callable[[Sequence[str]], dict[str, str]]
    clock: Callable[[], str]  # ISO timestamp for recorded_at
    places: Places  # loaded once by the composition root, read by the fixture fingerprint


@dataclass(frozen=True)
class CVEAudit:
    cve_id: str
    run_index: int  # within its target, in submission order
    report: AuditReport


@dataclass(frozen=True)
class TargetRuns:
    target: CVETarget
    grades: list[RunGrade]
    completed: bool
    audits: list[CVEAudit]


@dataclass(frozen=True)
class GatedSession:
    """Fixed before any audit. `tree` is set exactly when the run records."""

    options: CVEOptions
    harness: CVEHarness
    files: Baselines  # every file read at start, orphans included
    tree: TreeState | None

    def baselines(self) -> Baselines:
        return {cve_id: b for cve_id, b in self.files.items() if cve_id in _BENCHMARKED}

    def orphans(self) -> list[str]:
        return [f"{cve_id}.json" for cve_id in sorted(self.files) if cve_id not in _BENCHMARKED]


_BENCHMARKED = frozenset(target.cve_id for target in CVE_TARGETS)
