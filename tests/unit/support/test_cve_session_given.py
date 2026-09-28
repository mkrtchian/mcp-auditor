import asyncio
from dataclasses import dataclass, field
from pathlib import Path

from evals.cve_baseline import CVERunConditions, CVETargetBaseline, fixture_fingerprint
from evals.cve_baseline import write_baseline as _write_baseline
from evals.cve_grammar import CVEStatus, MissClass, RunGrade
from evals.cve_session import AuditTarget, CVEHarness, CVEOptions
from evals.cve_targets import CVE_TARGETS, CVETarget
from evals.eval_session import TreeState
from tests.unit.support.test_cve_gate_given import (
    a_gated_baseline,
    an_exploratory_baseline,
    conditions,
)
from tests.unit.support.test_cve_oracle_given import a_detected_grade, a_missed_grade

__all__ = ["a_detected_grade", "conditions"]

KUBERNETES = next(target for target in CVE_TARGETS if target.cve_id == "CVE-2025-53355")
SYMLINK = next(target for target in CVE_TARGETS if target.cve_id == "CVE-2025-53109")
COMMIT = "0123abc"
RECORDED_AT = "2026-09-28T12:00:00+00:00"


def a_miss() -> RunGrade:
    return a_missed_grade(MissClass.NOT_AIMED)


@dataclass
class ScriptedAudit:
    """Plays each target's script in order, then detects."""

    scripts: dict[str, list[RunGrade | None]] = field(default_factory=lambda: {})
    calls: list[str] = field(default_factory=lambda: [])

    async def __call__(self, target: CVETarget) -> RunGrade | None:
        self.calls.append(target.cve_id)
        script = self.scripts.get(target.cve_id)
        return script.pop(0) if script else a_detected_grade()


@dataclass
class OverlappingAudit:
    """Detects once every expected target has started an audit, and waits until then."""

    expected: set[str]
    started: set[str] = field(default_factory=lambda: set[str]())
    all_started: asyncio.Event = field(default_factory=asyncio.Event)

    async def __call__(self, target: CVETarget) -> RunGrade | None:
        self.started.add(target.cve_id)
        if self.started >= self.expected:
            self.all_started.set()
        await self.all_started.wait()
        return a_detected_grade()


def a_harness(audit: AuditTarget, baselines: Path, tree: TreeState | None = None) -> CVEHarness:
    return CVEHarness(
        audit=audit,
        baselines=baselines,
        read_tree=lambda: tree or TreeState(commit=COMMIT, dirty=False),
        image_ids=lambda names: {name: f"sha256:{name}" for name in names},
        clock=lambda: RECORDED_AT,
    )


def options(
    targets: list[CVETarget] | None = None,
    run_conditions: CVERunConditions | None = None,
    ungated: bool = False,
    record_baseline: bool = False,
) -> CVEOptions:
    return CVEOptions(
        targets=targets or [KUBERNETES],
        conditions=run_conditions or conditions(),
        ungated=ungated,
        record_baseline=record_baseline,
    )


def a_gated_file(directory: Path, target: CVETarget = KUBERNETES, budget: int = 10) -> None:
    baseline = a_gated_baseline(target.cve_id)
    _write(directory, baseline, target, conditions(budget))


def a_file_holding_one_run_of_three(directory: Path, target: CVETarget = KUBERNETES) -> None:
    baseline = an_exploratory_baseline([CVEStatus.DETECTED], target.cve_id)
    _write(directory, baseline, target, conditions())


def an_orphaned_file(directory: Path) -> str:
    _write_baseline(directory, a_gated_baseline("CVE-1999-0001"))
    return "CVE-1999-0001.json"


def _write(
    directory: Path, baseline: CVETargetBaseline, target: CVETarget, recorded: CVERunConditions
) -> None:
    update = {"fixture_fingerprint": fixture_fingerprint(target), "conditions": recorded}
    _write_baseline(directory, baseline.model_copy(update=update))
