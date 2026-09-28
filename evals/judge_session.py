"""One gated run of the judge isolation eval (ADR 025): the runs, the replays of flipped cases
and the recording, with the judge, git, the declarations and the clock injected."""

import asyncio
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from pydantic import ValidationError

from evals.baseline import BaselineStatus
from evals.concurrency import bounded
from evals.declared_flips import (
    ActiveDeclarations,
    DeclaredFlip,
    active_declarations,
    declaration_problems,
)
from evals.eval_session import (
    RECORDING_REFUSED,
    REFUSED_BEFORE_ANY_LLM_CALL,
    Refused,
    TreeState,
    tree_drift,
)
from evals.gate import CellOutcome, Observation, ReplayRule
from evals.gate_verdict import GateMode, GateVerdict
from evals.judge_baseline import (
    JudgeBaseline,
    JudgeConditions,
    judge_baseline_integrity,
    judge_condition_mismatches,
    load_judge_baseline,
    write_judge_baseline,
)
from evals.judge_fixture import JudgeCase, JudgeFixture, ground_truth_of, inputs_fingerprint
from evals.judge_gate import (
    CaseRuns,
    JudgeGateInput,
    JudgeGateResult,
    compare_cases,
    judge_case_gate,
    judge_ci_condition_mismatches,
    observe_case,
)
from evals.judge_recording import (
    JudgeRecording,
    decide_judge_recording,
    judge_condition_refusals,
    judge_exploratory_commit_refusal,
    judge_rescore_refusals,
)
from evals.recording import RecordingRefused
from mcp_auditor.config import Settings
from mcp_auditor.domain.models import EvalVerdict

type JudgeCall = Callable[[JudgeCase], Awaitable[EvalVerdict | None]]
"""One judge call on one case, None when the judge gave no verdict. The session may call it
concurrently."""

NOT_COMPARABLE_EXIT = 3

_EXIT_CODES = {
    GateVerdict.GREEN: 0,
    GateVerdict.RED: 1,
    GateVerdict.NOT_COMPARABLE: NOT_COMPARABLE_EXIT,
}


@dataclass(frozen=True)
class JudgeOptions:
    settings: Settings
    runs: int
    record_baseline: bool
    ungated: bool
    concurrency: int


@dataclass(frozen=True)
class JudgeHarness:
    judge: JudgeCall
    baseline_path: Path
    read_tree: Callable[[], TreeState]
    declarations: Callable[[], tuple[list[DeclaredFlip], bool]]
    clock: Callable[[], datetime]


@dataclass(frozen=True)
class JudgeSessionResult:
    conditions: JudgeConditions
    runs: CaseRuns
    gate: JudgeGateResult
    declarations: ActiveDeclarations
    written: JudgeBaseline | None
    recording_refused: list[str]
    exit_code: int


@dataclass(frozen=True)
class _Session:
    """Fixed before any judge call. `baseline` is None under --ungated, and `tree` is set
    exactly when the run records."""

    fixture: JudgeFixture
    ground_truth: dict[str, EvalVerdict]
    conditions: JudgeConditions
    baseline: JudgeBaseline | None
    tree: TreeState | None
    declarations: ActiveDeclarations


async def run_judge_gate(
    options: JudgeOptions, fixture: JudgeFixture, harness: JudgeHarness
) -> JudgeSessionResult:
    """Raises Refused on a run that cannot be compared or recorded before it starts."""
    session = _open(options, fixture, harness)
    judge = bounded(harness.judge, options.concurrency)
    runs = await _judge_runs(fixture, options.runs, judge)
    gate = await _gate(session, runs, judge)
    written, refused = _record(session, runs, gate, harness)
    return JudgeSessionResult(
        conditions=session.conditions,
        runs=runs,
        gate=gate,
        declarations=session.declarations,
        written=written,
        recording_refused=refused,
        exit_code=_exit_code(session, gate, refused),
    )


def _open(options: JudgeOptions, fixture: JudgeFixture, harness: JudgeHarness) -> _Session:
    if options.record_baseline and options.ungated:
        reason = (
            "--record-baseline cannot run --ungated: a baseline records the conditions it gates"
        )
        raise Refused(RECORDING_REFUSED, [reason])
    ground_truth = ground_truth_of(fixture)
    baseline = None if options.ungated else _load_checked(harness.baseline_path, fixture)
    entries, dirty = harness.declarations()
    session = _Session(
        fixture=fixture,
        ground_truth=ground_truth,
        conditions=_conditions(options.settings, options.runs, fixture),
        baseline=baseline,
        tree=harness.read_tree() if options.record_baseline else None,
        declarations=active_declarations(entries, dirty),
    )
    reasons = _pre_run_refusals(session) + declaration_problems(entries, set(ground_truth))
    if reasons:
        raise Refused(REFUSED_BEFORE_ANY_LLM_CALL, reasons)
    return session


def _conditions(settings: Settings, runs: int, fixture: JudgeFixture) -> JudgeConditions:
    judge_model = settings.resolve_judge_model()
    return JudgeConditions(
        runs=runs,
        provider=settings.provider,
        judge_model=judge_model,
        judge_reasoning=settings.resolve_reasoning(judge_model),
        inputs_fingerprint=inputs_fingerprint(fixture),
    )


def _load_checked(path: Path, fixture: JudgeFixture) -> JudgeBaseline | None:
    try:
        baseline = load_judge_baseline(path)
    except ValidationError as error:
        reason = f"{path} is not a valid baseline: {error}"
        raise Refused(REFUSED_BEFORE_ANY_LLM_CALL, [reason]) from error
    if baseline is None:
        return None
    problems = judge_baseline_integrity(baseline, fixture)
    if problems:
        raise Refused(REFUSED_BEFORE_ANY_LLM_CALL, problems)
    return baseline


def _pre_run_refusals(session: _Session) -> list[str]:
    """What the file, the labels and the tree already decide. Another draw is not rescored:
    its baseline is not comparable, which the gate says."""
    reasons: list[str] = []
    baseline = session.baseline
    if baseline and baseline.conditions.inputs_fingerprint == session.conditions.inputs_fingerprint:
        reasons += judge_rescore_refusals(baseline, session.ground_truth)
    if session.tree is not None:
        reasons += _recording_refusals(session, session.tree)
    return reasons


def _recording_refusals(session: _Session, tree: TreeState) -> list[str]:
    reasons = [
        f"a baseline records the conditions CI runs at, {mismatch}"
        for mismatch in judge_ci_condition_mismatches(session.conditions)
    ]
    if tree.dirty:
        reasons.append("the git tree has tracked modifications: record from a clean tree")
    if session.baseline is not None:
        reasons += judge_exploratory_commit_refusal(session.baseline, tree.commit)
        reasons += judge_condition_refusals(session.baseline, session.conditions)
    return reasons


async def _judge_runs(fixture: JudgeFixture, runs: int, judge: JudgeCall) -> CaseRuns:
    async def one_run() -> dict[str, Observation]:
        verdicts = await asyncio.gather(*(judge(case) for case in fixture.cases))
        return {
            case.id: observe_case(verdict)
            for case, verdict in zip(fixture.cases, verdicts, strict=True)
        }

    return list(await asyncio.gather(*(one_run() for _ in range(runs))))


async def _gate(session: _Session, runs: CaseRuns, judge: JudgeCall) -> JudgeGateResult:
    baseline = session.baseline
    mismatches = (
        judge_condition_mismatches(baseline.conditions, session.conditions) if baseline else []
    )
    # No baseline, an exploratory one or --ungated: the floors alone (ADR 025).
    paired = baseline is not None and baseline.status == BaselineStatus.CONFIRMED
    mode = GateMode.PAIRED if paired else GateMode.FLOORS_ONLY
    replays: dict[str, list[bool]] = {}
    if baseline is not None and paired and not mismatches:
        replays = await _replay_flips(session, baseline, runs, judge)
    return judge_case_gate(
        JudgeGateInput(
            mode=mode,
            runs=runs,
            ground_truth=session.ground_truth,
            baseline=baseline,
            replays=replays,
            declared=session.declarations.keys,
            mismatches=mismatches,
        )
    )


async def _replay_flips(
    session: _Session, baseline: JudgeBaseline, runs: CaseRuns, judge: JudgeCall
) -> dict[str, list[bool]]:
    comparisons = compare_cases(baseline, runs, session.ground_truth, session.declarations.keys)
    flipped = [
        case
        for case in session.fixture.cases
        if case.id in comparisons and comparisons[case.id].outcome == CellOutcome.FLIP
    ]
    replayed = await asyncio.gather(
        *(
            _replay(case, session.ground_truth[case.id], baseline.replay_rule, judge)
            for case in flipped
        )
    )
    return {case.id: replays for case, replays in zip(flipped, replayed, strict=True)}


async def _replay(
    case: JudgeCase, expected: EvalVerdict, rule: ReplayRule, judge: JudgeCall
) -> list[bool]:
    """One judge call at a time, until the replay rule decides. A call with no verdict
    reproduces the flip, as an uncovered replay does for the honeypots."""
    replays: list[bool] = []
    while rule.decide_replays(replays) is None:
        observed = observe_case(await judge(case))
        replays.append(observed != Observation(expected.value))
    return replays


def _record(
    session: _Session, runs: CaseRuns, gate: JudgeGateResult, harness: JudgeHarness
) -> tuple[JudgeBaseline | None, list[str]]:
    if session.tree is None:
        return None, []
    drift = _recording_drift(session, session.tree, harness)
    if drift:
        return None, drift
    recording = JudgeRecording(
        conditions=session.conditions,
        commit=session.tree.commit,
        recorded_at=harness.clock().isoformat(),
        runs=runs,
        ground_truth=session.ground_truth,
    )
    decision = decide_judge_recording(session.baseline, recording, gate)
    if isinstance(decision, RecordingRefused):
        return None, decision.reasons
    write_judge_baseline(harness.baseline_path, decision)
    return decision, []


def _recording_drift(session: _Session, tree: TreeState, harness: JudgeHarness) -> list[str]:
    drift = tree_drift(tree, harness.read_tree())
    try:
        reloaded = load_judge_baseline(harness.baseline_path)
    except ValidationError as error:
        return [*drift, f"{harness.baseline_path} is not a valid baseline: {error}"]
    if reloaded != session.baseline:
        drift.append("the baseline file changed during the runs: record again")
    return drift


def _exit_code(session: _Session, gate: JudgeGateResult, refused: list[str]) -> int:
    if refused:
        return NOT_COMPARABLE_EXIT
    if session.tree is not None:
        return 0
    return _EXIT_CODES[gate.verdict]
