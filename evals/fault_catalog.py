"""The faults the harness injects, each on the role it targets, with what the gate is expected
to answer on the floors of ADR 022 against the fixture. The expectations are the assertions of
the integration test `tests/integration/test_gate_fault_injection.py`.
`evals/fault_injection_method.md` gives the reasoning.
"""

from collections.abc import Callable
from dataclasses import dataclass

from evals.fault_injection import (
    CategoryDroppingGenerator,
    ChainRefusingModel,
    FailingJudge,
    PassingJudge,
    RandomJudge,
    SilentJudge,
    lose_detections,
)
from evals.gate_verdict import GateVerdict
from evals.honeypots import AuditModels
from evals.metrics import VerdictMap
from mcp_auditor.domain.models import AuditCategory

SEED = 0
GREEN = GateVerdict.GREEN
RED = GateVerdict.RED
NO_STABLE_FAIL_CELL = "no planted FAIL cell is stable and correct"
NO_STABLE_PASS_CELL = "no PASS cell is stable and correct"


@dataclass(frozen=True)
class Expectation:
    paired: GateVerdict
    floors_only: GateVerdict
    recording_refused: bool
    reasons: tuple[str, ...]  # substrings expected among the gate's or the recording's reasons


@dataclass(frozen=True)
class Fault:
    name: str
    expectation: Expectation | None
    wrap: Callable[[AuditModels], AuditModels] | None = None
    loses_detections: bool = False

    def models(self, models: AuditModels) -> AuditModels:
        return self.wrap(models) if self.wrap else models

    def degrade(self, verdicts: VerdictMap, audit_index: int) -> VerdictMap:
        if not self.loses_detections:
            return verdicts
        return lose_detections(verdicts, SEED, audit_index)


FAULTS = [
    Fault(
        "judge_passes_everything",
        Expectation(RED, RED, True, ("recall", "regression", NO_STABLE_FAIL_CELL)),
        wrap=lambda models: AuditModels(llm=models.llm, judge_llm=PassingJudge()),
    ),
    Fault(
        "judge_fails_everything",
        Expectation(RED, RED, True, ("precision", "regression", NO_STABLE_PASS_CELL)),
        wrap=lambda models: AuditModels(llm=models.llm, judge_llm=FailingJudge()),
    ),
    Fault(
        "judge_fails_at_random",
        Expectation(RED, RED, True, ("precision",)),
        wrap=lambda models: AuditModels(llm=models.llm, judge_llm=RandomJudge(SEED)),
    ),
    Fault(
        "no_verdict",
        Expectation(RED, RED, True, ("recall", "distribution_coverage", "regression")),
        wrap=lambda models: AuditModels(llm=models.llm, judge_llm=SilentJudge()),
    ),
    Fault(
        "half_the_detections_lost",
        None,
        loses_detections=True,
    ),
    Fault(
        "generator_drops_error_handling",
        Expectation(RED, GREEN, False, ("regression",)),
        wrap=lambda models: AuditModels(
            llm=CategoryDroppingGenerator(models.llm, AuditCategory.ERROR_HANDLING),
            judge_llm=models.judge_llm,
        ),
    ),
    Fault(
        "provider_refuses_chain_steps",
        Expectation(GREEN, GREEN, False, ()),
        wrap=lambda models: AuditModels(
            llm=ChainRefusingModel(models.llm), judge_llm=models.judge_llm
        ),
    ),
]
