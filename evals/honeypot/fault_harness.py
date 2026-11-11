"""Plant one fault in the audit of the three honeypots and see what the gate does with it.

The faulted runs are judged by the production gate against the committed fixture, in the
paired and the floors-only modes, and a first recording of them is decided. The fault stays
active in the retests. What each fault models, what the gate is expected to do with it and
what this proves are in `evals/fault_injection_method.md`.
"""

import itertools
from collections.abc import AsyncGenerator, Mapping
from contextlib import AsyncExitStack, asynccontextmanager
from dataclasses import dataclass, field
from datetime import UTC, datetime

from pydantic import BaseModel

from evals.baseline import Baseline, baseline_integrity
from evals.declared_flips import ActiveDeclarations
from evals.eval_session import DEFAULT_RUNS, HoneypotSession
from evals.gate import Observation, cell_key
from evals.gate_outcome import GateMode, GateResult
from evals.honeypot.decision import RunsOutcome, decide_runs
from evals.honeypot.fault_catalog import Fault
from evals.honeypot.retest import Retester
from evals.honeypots import (
    HONEYPOTS,
    MERGED_GROUND_TRUTH,
    REPO_ROOT,
    AuditModels,
    ConnectedHoneypot,
    HoneypotConfig,
    audit_connected,
    audit_honeypots,
    connected,
)
from evals.metrics import HoneypotMetrics, VerdictMap, aggregate_verdicts, build_run_detail
from evals.recording import Recording, RecordingRefused, decide_recording
from mcp_auditor.config import Settings
from mcp_auditor.domain.models import AuditReport

FIXTURE_PATH = REPO_ROOT / "evals" / "fixtures" / "fault_injection_baseline.json"


class FaultResult(BaseModel):
    fault: str
    completed_runs: int
    observations: list[dict[str, Observation]]
    metrics: HoneypotMetrics
    paired: GateResult
    floors_only: GateResult
    recording_refusals: list[str]


def fixture_refusals(fixture: Baseline) -> list[str]:
    """A fixture made stale by a honeypot, label or model change is rebuilt, never compared
    against in silence."""
    return baseline_integrity(fixture, MERGED_GROUND_TRUTH)


@dataclass(frozen=True)
class Harness:
    fixture: Baseline
    base_models: AuditModels
    budget: int

    async def inject(self, fault: Fault) -> FaultResult:
        async with _connected_honeypots() as servers:
            audit = FaultedAudit(fault, fault.models(self.base_models), self.budget, servers)
            outcome = await audit.runs()
            retester = Retester(audit.retest, HONEYPOTS, announce=_ignore, warn=_ignore)
            paired = await decide_runs(self._session(GateMode.PAIRED, fault), outcome, retester)
            floors_only = await decide_runs(
                self._session(GateMode.FLOORS_ONLY, fault), outcome, retester
            )
        return FaultResult(
            fault=fault.name,
            completed_runs=len(outcome.details),
            observations=[
                {cell_key(cell): seen for cell, seen in run.items()}
                for run in outcome.observations()
            ],
            metrics=outcome.metrics()[0],
            paired=paired,
            floors_only=floors_only,
            recording_refusals=self._recording_refusals(outcome, floors_only),
        )

    def _session(self, mode: GateMode, fault: Fault) -> HoneypotSession:
        # Only satisfies the type: decide_runs never reads it, and model_construct skips the env.
        settings = Settings.model_construct(provider="openai", model="gpt-6-luna", reasoning="none")
        declarations = ActiveDeclarations(keys=_declared_keys(fault))
        return HoneypotSession(
            settings,
            self.fixture.conditions,
            self.fixture,
            mode,
            tree=None,
            declarations=declarations,
        )

    def _recording_refusals(self, outcome: RunsOutcome, floors_only: GateResult) -> list[str]:
        """A first recording of the faulted runs, with no baseline before it."""
        recording = Recording(
            conditions=self.fixture.conditions,
            commit="fault-injection",
            recorded_at=datetime.now(UTC).isoformat(),
            runs=outcome.observations(),
            metrics=outcome.metrics()[0],
            completed_all=outcome.completed_all(DEFAULT_RUNS),
            protected=outcome.protected(),
            ground_truth=MERGED_GROUND_TRUTH,
        )
        decision = decide_recording(None, recording, floors_only)
        return decision.reasons if isinstance(decision, RecordingRefused) else []


def _declared_keys(fault: Fault) -> frozenset[str]:
    return frozenset(cell_key(cell) for cell in MERGED_GROUND_TRUTH if cell[1] == fault.declares)


@asynccontextmanager
async def _connected_honeypots() -> AsyncGenerator[dict[str, ConnectedHoneypot]]:
    async with AsyncExitStack() as stack:
        yield {
            honeypot.name: await stack.enter_async_context(connected(honeypot))
            for honeypot in HONEYPOTS
        }


@dataclass(frozen=True)
class FaultedAudit:
    """The audit with the fault planted, shared by the runs and the retests, as are the
    servers. Every audit, a retest included, takes the next index, so a detection loss is
    drawn afresh at each."""

    fault: Fault
    models: AuditModels
    budget: int
    servers: Mapping[str, ConnectedHoneypot]
    audits: "itertools.count[int]" = field(default_factory=itertools.count)

    async def runs(self) -> RunsOutcome:
        outcome = RunsOutcome()
        for index in range(DEFAULT_RUNS):
            verdicts, report = await audit_honeypots(self._report)
            verdicts = self.fault.degrade(verdicts, next(self.audits))
            outcome.details.append(build_run_detail(index, verdicts, report, MERGED_GROUND_TRUTH))
            outcome.verdict_maps.append(verdicts)
            outcome.audits.append((index, report))
        return outcome

    async def retest(self, honeypot: HoneypotConfig) -> VerdictMap:
        # Taken before the audit: retests of different servers finish in any order.
        index = next(self.audits)
        verdicts = aggregate_verdicts(await self._report(honeypot))
        return self.fault.degrade(verdicts, index)

    async def _report(self, honeypot: HoneypotConfig) -> AuditReport:
        return await audit_connected(self.models, self.servers[honeypot.name], self.budget)


def _ignore(_message: str) -> None:
    pass
