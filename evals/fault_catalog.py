"""The faults the harness injects, each on the role it targets, with what the gate is expected
to answer on the floors of ADR 022. `evals/fault_injection_method.md` gives the reasoning.
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
from evals.honeypots import AuditModels
from evals.metrics import VerdictMap
from mcp_auditor.domain.models import AuditCategory

SEED = 0


@dataclass(frozen=True)
class Fault:
    name: str
    expected: str
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
        "red in both modes on recall (0 detections), PAIRED also on the regressions of the 3 "
        "stable and correct FAIL cells; recording refused on recall",
        wrap=lambda models: AuditModels(llm=models.llm, judge_llm=PassingJudge()),
    ),
    Fault(
        "judge_fails_everything",
        "red in both modes on precision, PAIRED also on the regressions of every PASS cell; "
        "recording refused on precision",
        wrap=lambda models: AuditModels(llm=models.llm, judge_llm=FailingJudge()),
    ),
    Fault(
        "judge_fails_at_random",
        "red in both modes on precision, PASS cells flipped; recording refused on precision",
        wrap=lambda models: AuditModels(llm=models.llm, judge_llm=RandomJudge(SEED)),
    ),
    Fault(
        "no_verdict",
        "red in both modes on recall and distribution_coverage, PAIRED also on the regressions "
        "(uncovered) of every stable and correct cell; recording refused on both",
        wrap=lambda models: AuditModels(llm=models.llm, judge_llm=SilentJudge()),
    ),
    Fault(
        "half_the_detections_lost",
        "PAIRED green unless a lost detection reproduces (about 0.19 each) or the detections "
        "fall under 3, FLOORS_ONLY green unless they fall under 3; recording accepted unless "
        "they fall under 3",
        loses_detections=True,
    ),
    Fault(
        "generator_drops_error_handling",
        "PAIRED red on the regressions (uncovered) of the 8 stable and correct error_handling "
        "cells, FLOORS_ONLY green (coverage 0.80 clears its floor); recording accepted",
        wrap=lambda models: AuditModels(
            llm=CategoryDroppingGenerator(models.llm, AuditCategory.ERROR_HANDLING),
            judge_llm=models.judge_llm,
        ),
    ),
    Fault(
        "provider_refuses_chain_steps",
        "green in both modes, no gated cell moves on the two chain-only flaws; recording accepted",
        wrap=lambda models: AuditModels(
            llm=ChainRefusingModel(models.llm), judge_llm=models.judge_llm
        ),
    ),
]
