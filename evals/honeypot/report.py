from pydantic import BaseModel

from evals.baseline import BaselineConditions
from evals.gate_outcome import GateResult
from evals.metrics import ConsistencyDetail, HoneypotMetrics, RunDetail


class HoneypotReport(BaseModel):
    timestamp: str
    commit: str
    dirty: bool
    conditions: BaselineConditions
    config: dict[str, int]
    metrics: HoneypotMetrics
    thresholds: dict[str, float]
    passed: bool
    gate: GateResult
    runs: list[RunDetail]
    consistency_details: dict[str, ConsistencyDetail]
