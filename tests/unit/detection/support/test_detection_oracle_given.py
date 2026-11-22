import re
from dataclasses import dataclass, field

from evals.cve.detection.gate import DetectionGateResult, TargetComparison
from evals.cve.detection.oracle import DetectionReport
from evals.cve.grammar import FlawClass
from evals.gate_outcome import GateOutcome
from tests.unit.detection.support.detection_reports import NONCE, a_detection_report


@dataclass(frozen=True)
class FakeTarget:
    flaw_id: str = "CVE-2025-0001"
    severity: str = "9.1 CRITICAL"
    nonce: str = NONCE
    classes: frozenset[FlawClass] = frozenset({FlawClass.READ_OUTSIDE_SCOPE})
    aim: re.Pattern[str] = field(default=re.compile(r"^/outside/"))
    awaited_capability: str | None = "declared-scope awareness"
    note: str = "test note"


@dataclass
class FakeOutOfScopeFlaw:
    flaw_id: str
    severity: str
    reason: str


def a_report_gated_on(*targets: TargetComparison) -> DetectionReport:
    gate = DetectionGateResult(outcome=GateOutcome.GREEN, reasons=[], targets=list(targets))
    return a_detection_report([]).model_copy(update={"gate": gate})
