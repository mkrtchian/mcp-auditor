from collections.abc import Callable
from dataclasses import dataclass, field, replace
from pathlib import Path

import tests.unit.support.acceptance_targets as acceptance
from evals.cve.detection.baseline import (
    DetectionBaseline,
    DetectionRunConditions,
    fixture_fingerprint,
    write_baseline,
)
from evals.cve.detection.layout_check import LayoutCheck
from evals.cve.detection.session_model import (
    AuditTarget,
    CheckTarget,
    DetectionHarness,
    DetectionOptions,
    GradedAudit,
    ObserveLayout,
)
from evals.cve.detection.targets import Target
from evals.cve.grammar import MissKind, RunGrade, TargetStatus
from evals.cve.places import DETECTION_PLACES, load_places
from evals.eval_session import TreeState
from tests.unit.cve.support.test_cve_grammar_given import a_report
from tests.unit.detection.support.layouts import SOUND_LAYOUT
from tests.unit.detection.support.test_detection_gate_given import (
    a_gated_baseline,
    conditions,
)
from tests.unit.detection.support.test_detection_oracle_given import (
    a_detected_grade,
    a_missed_grade,
)

# The real loaded places, so the real targets' kept ids resolve (fixture_fingerprint and the
# session both read them); no Docker, load_places only reads the frozen JSON.
PLACES = load_places(DETECTION_PLACES)
KUBERNETES = acceptance.an_acceptance_target(acceptance.KUBERNETES)
SYMLINK = acceptance.an_acceptance_target(acceptance.FILESYSTEM)
COMMIT = "0123abc"
RECORDED_AT = "2026-09-28T12:00:00+00:00"


def a_miss() -> RunGrade:
    return a_missed_grade(MissKind.NOT_AIMED)


def an_unchecked_detected_grade() -> RunGrade:
    """A detection the replay could not check: it reads detected now, but a miss once every
    unchecked credit counts as one, so its status depends on the unchecked credits."""
    return RunGrade(
        status=TargetStatus.DETECTED,
        surfaced_places=frozenset({"planted"}),
        unchecked_places=frozenset({"planted"}),
        status_if_unchecked_missed=TargetStatus.MISSED,
        aimed=True,
    )


@dataclass
class ScriptedAudit:
    """Plays each target's script in order, then detects. Each report is named after the
    audit that made it, `audit_name(flaw_id, n)` for the target's n-th call."""

    scripts: dict[str, list[RunGrade | None]] = field(
        default_factory=dict[str, list[RunGrade | None]]
    )
    calls: list[str] = field(default_factory=list[str])

    async def __call__(self, target: Target) -> GradedAudit | None:
        name = audit_name(target.flaw_id, self.calls.count(target.flaw_id))
        self.calls.append(target.flaw_id)
        script = self.scripts.get(target.flaw_id)
        grade = script.pop(0) if script else a_detected_grade()
        return None if grade is None else GradedAudit(grade, a_report(server_command=name))


def audit_name(flaw_id: str, call: int) -> str:
    return f"{flaw_id} audit {call}"


@dataclass
class ScriptedCheck:
    """The pre-run check: each target's out-of-calibration reasons, empty (in calibration) by
    default. Raises `error` to stand for a configuration error."""

    conditions: dict[str, list[str]] = field(default_factory=dict[str, list[str]])
    error: Exception | None = None

    async def __call__(self, target: Target) -> list[str]:
        if self.error is not None:
            raise self.error
        return self.conditions.get(target.flaw_id, [])


BROKEN_LAYOUT = replace(SOUND_LAYOUT, breaks=True)


@dataclass
class ScriptedLayout:
    """The layout and route checks: each target's observed layout, sound by default."""

    layouts: dict[str, LayoutCheck] = field(default_factory=dict[str, LayoutCheck])

    async def __call__(self, target: Target) -> LayoutCheck:
        return self.layouts.get(target.flaw_id, SOUND_LAYOUT)


def a_harness(
    audit: AuditTarget,
    baselines: Path,
    tree: TreeState | None = None,
    check: CheckTarget | None = None,
    announce: Callable[[int], None] = lambda _: None,
    layout: ObserveLayout | None = None,
) -> DetectionHarness:
    return DetectionHarness(
        audit=audit,
        check=check or ScriptedCheck(),
        layout=layout or ScriptedLayout(),
        announce_audits=announce,
        baselines=baselines,
        read_tree=lambda: tree or TreeState(commit=COMMIT, dirty=False),
        image_ids=lambda names: {name: f"sha256:{name}" for name in names},
        clock=lambda: RECORDED_AT,
        places=PLACES,
    )


def options(
    targets: list[Target] | None = None,
    run_conditions: DetectionRunConditions | None = None,
    no_baseline: bool = False,
    record_baseline: bool = False,
) -> DetectionOptions:
    return DetectionOptions(
        targets=targets or [KUBERNETES],
        conditions=run_conditions or conditions(),
        no_baseline=no_baseline,
        record_baseline=record_baseline,
    )


def a_gated_file(directory: Path, target: Target = KUBERNETES, budget: int = 10) -> None:
    baseline = a_gated_baseline(target.flaw_id)
    a_baseline_file(directory, baseline, target, conditions(budget))


def a_baseline_file(
    directory: Path, baseline: DetectionBaseline, target: Target, recorded: DetectionRunConditions
) -> None:
    update = {"fixture_fingerprint": fixture_fingerprint(target, PLACES), "conditions": recorded}
    write_baseline(directory, baseline.model_copy(update=update))
