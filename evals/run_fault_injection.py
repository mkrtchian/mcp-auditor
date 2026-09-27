"""Plant one fault in the audit of the three honeypots and see what the gate does with it
(`uv run python -m evals.run_fault_injection [--fault NAME ...]`).

The faulted runs are judged by the production gate against the committed fixture, in the
paired and the floors-only modes, and a first recording of them is decided. The fault stays
active in the replays. What each fault models and what the gate is expected to do with it are
in `evals/fault_injection_method.md`. Real calls on the configured models, never in CI.
"""

import argparse
import asyncio
import itertools
import sys
import traceback
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import NoReturn

from pydantic import BaseModel

from evals.baseline import Baseline, BaselineConditions, baseline_integrity, load_baseline
from evals.eval_session import (
    DEFAULT_BUDGET,
    DEFAULT_RUNS,
    REFUSED_BEFORE_ANY_LLM_CALL,
    EvalOptions,
    EvalSession,
    candidate_conditions,
)
from evals.fault_catalog import FAULTS, Fault
from evals.gate_verdict import GateMode, GateResult
from evals.honeypots import (
    HONEYPOTS,
    MERGED_GROUND_TRUTH,
    REPO_ROOT,
    AuditModels,
    HoneypotConfig,
    audit_honeypot,
    audit_honeypots,
    models_for,
)
from evals.judging import RunsOutcome, judge_runs
from evals.metrics import EvalMetrics, VerdictMap, aggregate_verdicts, build_run_detail
from evals.recording import Recording, RecordingRefused, condition_refusals, decide_recording
from evals.replay import Replayer
from mcp_auditor.config import Settings, load_settings
from mcp_auditor.domain.models import AuditReport

FIXTURE_PATH = REPO_ROOT / "evals" / "fixtures" / "fault_injection_baseline.json"
REPORT_PATH = REPO_ROOT / "output" / "fault_injection_report.json"
REFUSED_EXIT = 3


class FaultResult(BaseModel):
    fault: str
    expected: str
    completed_runs: int
    metrics: EvalMetrics
    paired: GateResult
    floors_only: GateResult
    recording_refusals: list[str]


class FaultInjectionReport(BaseModel):
    timestamp: str
    fixture_commit: str
    results: list[FaultResult]
    failed: list[str]


def fixture_refusals(fixture: Baseline, conditions: BaselineConditions) -> list[str]:
    """A fixture made stale by a honeypot, label or model change is rebuilt, never compared
    against in silence."""
    return condition_refusals(fixture, conditions) + baseline_integrity(
        fixture, MERGED_GROUND_TRUTH
    )


def main() -> None:
    faults = _parse_args()
    harness = _harness_or_refused()
    report = asyncio.run(harness.inject_all(faults))
    REPORT_PATH.parent.mkdir(parents=True, exist_ok=True)
    REPORT_PATH.write_text(report.model_dump_json(indent=2))
    print(f"Report written to {REPORT_PATH}")


def _parse_args() -> list[Fault]:
    by_name = {fault.name: fault for fault in FAULTS}
    parser = argparse.ArgumentParser(
        description=(
            "Plant a fault in the honeypot audit and judge it with the gate against "
            "evals/fixtures/fault_injection_baseline.json (real LLM calls, never in CI)"
        )
    )
    parser.add_argument(
        "--fault",
        nargs="+",
        choices=list(by_name),
        default=list(by_name),
        metavar="NAME",
        help=f"the faults to inject, all by default: {', '.join(by_name)}",
    )
    return [by_name[name] for name in parser.parse_args().fault]


def _harness_or_refused() -> "Harness":
    settings = load_settings()
    options = EvalOptions(
        DEFAULT_RUNS, DEFAULT_BUDGET, str(REPORT_PATH), record_baseline=False, ungated=False
    )
    try:
        conditions = candidate_conditions(settings, options)
    except ValueError as error:
        _refuse([str(error)])
    fixture = load_baseline(FIXTURE_PATH)
    if fixture is None:
        _refuse([f"{FIXTURE_PATH} is missing"])
    reasons = fixture_refusals(fixture, conditions)
    if reasons:
        _refuse(reasons)
    return Harness(settings, conditions, fixture)


def _refuse(reasons: list[str]) -> NoReturn:
    print(REFUSED_BEFORE_ANY_LLM_CALL, *[f"- {reason}" for reason in reasons], sep="\n")
    raise SystemExit(REFUSED_EXIT)


@dataclass(frozen=True)
class Harness:
    settings: Settings
    conditions: BaselineConditions
    fixture: Baseline

    async def inject_all(self, faults: list[Fault]) -> FaultInjectionReport:
        results: list[FaultResult] = []
        failed: list[str] = []
        for fault in faults:
            print(f"Injecting {fault.name}...")
            try:
                results.append(await self.inject(fault))
            except Exception:
                print(f"Warning: {fault.name} failed:")
                traceback.print_exc(file=sys.stderr)
                failed.append(fault.name)
                continue
            _print_result(results[-1])
        return FaultInjectionReport(
            timestamp=datetime.now(UTC).isoformat(),
            fixture_commit=self.fixture.commit,
            results=results,
            failed=failed,
        )

    async def inject(self, fault: Fault) -> FaultResult:
        audit = FaultedAudit(fault, fault.models(models_for(self.settings)))
        outcome = await audit.runs()
        if not outcome.details:
            raise RuntimeError("no run completed: nothing to judge")
        replayer = Replayer(audit.replay, HONEYPOTS, announce=print, warn=_warn)
        paired = await judge_runs(self._session(GateMode.PAIRED), outcome, replayer)
        floors_only = await judge_runs(self._session(GateMode.FLOORS_ONLY), outcome, replayer)
        return FaultResult(
            fault=fault.name,
            expected=fault.expected,
            completed_runs=len(outcome.details),
            metrics=outcome.metrics()[0],
            paired=paired,
            floors_only=floors_only,
            recording_refusals=self._recording_refusals(outcome, floors_only),
        )

    def _session(self, mode: GateMode) -> EvalSession:
        return EvalSession(self.settings, self.conditions, self.fixture, mode, tree=None)

    def _recording_refusals(self, outcome: RunsOutcome, floors_only: GateResult) -> list[str]:
        """A first recording of the faulted runs, with no baseline before it."""
        recording = Recording(
            conditions=self.conditions,
            commit="fault-injection",
            recorded_at=datetime.now(UTC).isoformat(),
            runs=outcome.observations(),
            metrics=outcome.metrics()[0],
            completed_all=outcome.completed_all(DEFAULT_RUNS),
            protected=outcome.protected(),
        )
        decision = decide_recording(None, recording, floors_only)
        return decision.reasons if isinstance(decision, RecordingRefused) else []


@dataclass(frozen=True)
class FaultedAudit:
    """The audit with the fault planted, shared by the runs and the replays. Every audit, a
    replay included, takes the next index, so a detection loss is drawn afresh at each."""

    fault: Fault
    models: AuditModels
    audits: "itertools.count[int]" = field(default_factory=itertools.count)

    async def runs(self) -> RunsOutcome:
        outcome = RunsOutcome()
        for index in range(DEFAULT_RUNS):
            try:
                verdicts, report = await audit_honeypots(self._report)
            except Exception:
                print(f"Warning: run {index + 1}/{DEFAULT_RUNS} failed:")
                traceback.print_exc(file=sys.stderr)
                continue
            verdicts = self.fault.degrade(verdicts, next(self.audits))
            outcome.details.append(build_run_detail(index, verdicts, report, MERGED_GROUND_TRUTH))
            outcome.verdict_maps.append(verdicts)
            outcome.audits.append((index, report))
        return outcome

    async def replay(self, honeypot: HoneypotConfig) -> VerdictMap:
        verdicts = aggregate_verdicts(await self._report(honeypot))
        return self.fault.degrade(verdicts, next(self.audits))

    async def _report(self, honeypot: HoneypotConfig) -> AuditReport:
        print(f"  Auditing {honeypot.name}...")
        return await audit_honeypot(self.models, honeypot, DEFAULT_BUDGET)


def _warn(message: str) -> None:
    print(message, file=sys.stderr, end="")


def _print_result(result: FaultResult) -> None:
    print(f"{result.fault}, {result.completed_runs} of {DEFAULT_RUNS} runs completed")
    print(f"  expected: {result.expected}")
    for gate in (result.paired, result.floors_only):
        _print_observed(f"{gate.mode} {gate.verdict}", gate.reasons)
    refusals = result.recording_refusals
    _print_observed("recording refused" if refusals else "recording accepted", refusals)


def _print_observed(outcome: str, reasons: list[str]) -> None:
    print(f"  observed: {outcome}")
    for reason in reasons:
        print(f"    - {reason}")


if __name__ == "__main__":
    main()
