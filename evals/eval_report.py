from pydantic import BaseModel

from evals.baseline import BaselineConditions
from evals.gate_verdict import GateResult
from evals.metrics import ConsistencyDetail, EvalMetrics, RunDetail


class EvalReport(BaseModel):
    timestamp: str
    commit: str
    dirty: bool
    conditions: BaselineConditions
    config: dict[str, int]
    metrics: EvalMetrics
    thresholds: dict[str, float]
    passed: bool
    gate: GateResult
    runs: list[RunDetail]
    consistency_details: dict[str, ConsistencyDetail]
