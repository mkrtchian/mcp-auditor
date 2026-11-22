import asyncio
from dataclasses import dataclass, field
from pathlib import Path

from evals.cve.detection.baseline import write_baseline
from evals.cve.detection.session_model import GradedAudit
from evals.cve.detection.targets import Target
from evals.cve.grammar import TargetStatus
from tests.unit.detection.support.detection_reports import a_detected_grade
from tests.unit.detection.support.detection_sessions import (
    KUBERNETES,
    ScriptedAudit,
    a_baseline_file,
)
from tests.unit.detection.support.test_detection_gate_given import (
    a_gated_baseline,
    an_unconfirmed_baseline,
    conditions,
)
from tests.unit.support.grammar_inputs import a_report


@dataclass
class OverlappingAudit:
    """Detects once every expected target has started an audit, and waits until then."""

    expected: set[str]
    started: set[str] = field(default_factory=lambda: set[str]())
    all_started: asyncio.Event = field(default_factory=asyncio.Event)

    async def __call__(self, target: Target) -> GradedAudit | None:
        self.started.add(target.flaw_id)
        if self.started >= self.expected:
            self.all_started.set()
        await self.all_started.wait()
        return GradedAudit(a_detected_grade(), a_report())


@dataclass
class RecordingAnnounce:
    """Records each announced audit count, with the audits already started at that moment."""

    audit: ScriptedAudit
    announced: list[tuple[int, int]] = field(default_factory=list[tuple[int, int]])

    def __call__(self, audits: int) -> None:
        self.announced.append((audits, len(self.audit.calls)))


def a_file_holding_one_run_of_three(directory: Path, target: Target = KUBERNETES) -> None:
    baseline = an_unconfirmed_baseline([TargetStatus.DETECTED], target.flaw_id)
    a_baseline_file(directory, baseline, target, conditions())


def an_orphaned_file(directory: Path) -> str:
    write_baseline(directory, a_gated_baseline("CVE-1999-0001"))
    return "CVE-1999-0001.json"
