"""One gated run of the judge isolation eval (ADR 025): the runs, the replays of flipped cases
and the recording, with the judge, git, the declarations and the clock injected."""

import asyncio
from dataclasses import replace
from pathlib import Path

from pydantic import ValidationError

from evals.baseline import BaselineStatus
from evals.concurrency import bounded
from evals.declared_flips import active_declarations, declaration_problems
from evals.eval_session import RECORDING_REFUSED, REFUSED_BEFORE_ANY_LLM_CALL, Refused
from evals.gate import Observation
from evals.gate_verdict import GateMode, GateVerdict
from evals.judge_baseline import (
    JudgeBaseline,
    JudgeConditions,
    judge_baseline_integrity,
    judge_condition_mismatches,
    load_judge_baseline,
)
from evals.judge_fixture import JudgeFixture, ground_truth_of, inputs_fingerprint
from evals.judge_gate import (
    CaseRuns,
    JudgeGateInput,
    JudgeGateResult,
    judge_case_gate,
    observe_case,
)
from evals.judge_recording import judge_rescore_refusals
from evals.judge_replay import JudgeCall, ReplayContext, replay_flips, reproductions
from evals.judge_session_model import JudgeHarness, JudgeOptions, JudgeSession, JudgeSessionResult
from evals.judge_session_recording import record, recording_refusals
from mcp_auditor.config import Settings

NOT_COMPARABLE_EXIT = 3

_EXIT_CODES = {
    GateVerdict.GREEN: 0,
    GateVerdict.RED: 1,
    GateVerdict.NOT_COMPARABLE: NOT_COMPARABLE_EXIT,
}


async def run_judge_gate(
    options: JudgeOptions, fixture: JudgeFixture, harness: JudgeHarness
) -> JudgeSessionResult:
    """Raises Refused on a run that cannot be compared or recorded before it starts."""
    session = _open(options, fixture, harness)
    runs = await _judge_runs(fixture, options.runs, session.judge)
    gate, replay_observations = await _gate(session, runs)
    written, refused = record(session, runs, gate)
    return JudgeSessionResult(
        conditions=session.conditions,
        runs=runs,
        gate=gate,
        baseline=session.baseline,
        replay_observations=replay_observations,
        throttled_judgments=list(harness.throttled_judgments()),
        declarations=session.declarations,
        written=written,
        recording_refused=refused,
        exit_code=_exit_code(session, gate, refused),
    )


def _open(options: JudgeOptions, fixture: JudgeFixture, harness: JudgeHarness) -> JudgeSession:
    if options.record_baseline and options.ungated:
        reason = (
            "--record-baseline cannot run --ungated: a baseline records the conditions it gates"
        )
        raise Refused(RECORDING_REFUSED, [reason])
    ground_truth = ground_truth_of(fixture)
    baseline = None if options.ungated else _load_checked(harness.baseline_path, fixture)
    entries, dirty = harness.declarations()
    session = JudgeSession(
        harness=harness,
        judge=bounded(harness.judge, options.concurrency),
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


def _pre_run_refusals(session: JudgeSession) -> list[str]:
    """What the file, the labels and the tree already decide. Another draw is not rescored:
    its baseline is not comparable, which the gate says."""
    reasons: list[str] = []
    baseline = session.baseline
    if baseline and baseline.conditions.inputs_fingerprint == session.conditions.inputs_fingerprint:
        reasons += judge_rescore_refusals(baseline, session.ground_truth)
    if session.tree is not None:
        reasons += recording_refusals(session, session.tree)
    return reasons


async def _judge_runs(fixture: JudgeFixture, runs: int, judge: JudgeCall) -> CaseRuns:
    async def one_run() -> dict[str, Observation]:
        verdicts = await asyncio.gather(*(judge(case) for case in fixture.cases))
        return {
            case.id: observe_case(verdict)
            for case, verdict in zip(fixture.cases, verdicts, strict=True)
        }

    return list(await asyncio.gather(*(one_run() for _ in range(runs))))


async def _gate(
    session: JudgeSession, runs: CaseRuns
) -> tuple[JudgeGateResult, dict[str, list[Observation]]]:
    baseline = session.baseline
    mismatches = (
        judge_condition_mismatches(baseline.conditions, session.conditions) if baseline else []
    ) + _throttle_mismatches(session)
    observations: dict[str, list[Observation]] = {}
    if baseline is not None and _paired(session) and not mismatches:
        observations = await replay_flips(_replay_context(session), baseline, runs)
        # A throttled replay reads as reproduced, so it would turn the gate red.
        mismatches = _throttle_mismatches(session)
    gate_input = _gate_input(session, runs, observations)
    return judge_case_gate(replace(gate_input, mismatches=mismatches)), observations


def _throttle_mismatches(session: JudgeSession) -> list[str]:
    throttled = len(session.harness.throttled_judgments())
    if not throttled:
        return []
    return [
        f"{throttled} judgment(s) throttled by the model provider past every retry:"
        " the run cannot be compared"
    ]


def _gate_input(
    session: JudgeSession, runs: CaseRuns, observations: dict[str, list[Observation]]
) -> JudgeGateInput:
    return JudgeGateInput(
        mode=GateMode.PAIRED if _paired(session) else GateMode.FLOORS_ONLY,
        runs=runs,
        ground_truth=session.ground_truth,
        baseline=session.baseline,
        replays={
            case: reproductions(replays, session.ground_truth[case])
            for case, replays in observations.items()
        },
        declared=session.declarations.keys,
    )


def _paired(session: JudgeSession) -> bool:
    """No baseline, an exploratory one or --ungated: the floors alone (ADR 025)."""
    baseline = session.baseline
    return baseline is not None and baseline.status == BaselineStatus.CONFIRMED


def _replay_context(session: JudgeSession) -> ReplayContext:
    return ReplayContext(
        judge=session.judge,
        ground_truth=session.ground_truth,
        declared=session.declarations.keys,
        cases=session.fixture.cases,
        announce=session.harness.on_replays,
    )


def _exit_code(session: JudgeSession, gate: JudgeGateResult, refused: list[str]) -> int:
    if refused:
        return NOT_COMPARABLE_EXIT
    if session.tree is not None:
        return 0
    return _EXIT_CODES[gate.verdict]
