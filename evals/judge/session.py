"""One gated run of the judge eval (ADR 025): the runs, the retests of flipped cases
and the recording, with the judge, git, the declarations and the clock injected."""

import asyncio
from dataclasses import replace
from pathlib import Path

from pydantic import ValidationError

from evals.baseline import BaselineStatus
from evals.concurrency import bounded
from evals.declared_flips import active_declarations, declaration_problems
from evals.eval_session import (
    RECORD_WITHOUT_BASELINE,
    RECORDING_REFUSED,
    REFUSED_BEFORE_ANY_LLM_CALL,
    Refused,
)
from evals.gate import Observation
from evals.gate_outcome import NOT_COMPARABLE_EXIT, GateMode
from evals.judge.baseline import (
    JudgeBaseline,
    judge_baseline_integrity,
    judge_condition_mismatches,
    judge_conditions,
    load_judge_baseline,
)
from evals.judge.fixture import JudgeFixture, ground_truth_of, inputs_fingerprint
from evals.judge.gate import (
    CaseRuns,
    JudgeGateInput,
    JudgeGateResult,
    decide_judge_gate,
)
from evals.judge.recording import judge_rescore_refusals
from evals.judge.retest import (
    JudgeCall,
    JudgeCallVerdict,
    RetestContext,
    reproductions,
    retest_flips,
)
from evals.judge.session_model import JudgeHarness, JudgeOptions, JudgeSession, JudgeSessionResult
from evals.judge.session_recording import record, recording_refusals

type RunAnswers = list[dict[str, JudgeCallVerdict]]
type RetestAnswers = dict[str, list[JudgeCallVerdict]]


async def run_judge_gate(
    options: JudgeOptions, fixture: JudgeFixture, harness: JudgeHarness
) -> JudgeSessionResult:
    """Raises Refused on a run that cannot be compared or recorded before it starts."""
    session = _open(options, fixture, harness)
    answers = await _judge_runs(fixture, options.runs, session.judge)
    runs = [
        {case: Observation.of(answer.verdict) for case, answer in run.items()} for run in answers
    ]
    run_throttled = _throttled_in_runs(answers)
    gate, retests = await _gate(session, runs, run_throttled)
    written, refused = record(session, runs, gate)
    return JudgeSessionResult(
        conditions=session.conditions,
        runs=runs,
        gate=gate,
        baseline=session.baseline,
        retest_observations=_observations(retests),
        throttled_judgments=run_throttled + _throttled_in_retests(retests),
        declarations=session.declarations,
        written=written,
        recording_refused=refused,
        exit_code=_exit_code(session, gate, refused),
    )


def _open(options: JudgeOptions, fixture: JudgeFixture, harness: JudgeHarness) -> JudgeSession:
    if options.record_baseline and options.no_baseline:
        raise Refused(RECORDING_REFUSED, [RECORD_WITHOUT_BASELINE])
    ground_truth = ground_truth_of(fixture)
    baseline = None if options.no_baseline else _load_checked(harness.baseline_path, fixture)
    entries, dirty = harness.declarations()
    session = JudgeSession(
        harness=harness,
        judge=bounded(harness.judge, options.concurrency),
        fixture=fixture,
        ground_truth=ground_truth,
        conditions=judge_conditions(options.settings, options.runs, inputs_fingerprint(fixture)),
        baseline=baseline,
        tree=harness.read_tree() if options.record_baseline else None,
        declarations=active_declarations(entries, dirty),
    )
    reasons = _pre_run_refusals(session) + declaration_problems(entries, set(ground_truth))
    if reasons:
        raise Refused(REFUSED_BEFORE_ANY_LLM_CALL, reasons)
    return session


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


async def _judge_runs(fixture: JudgeFixture, runs: int, judge: JudgeCall) -> RunAnswers:
    async def one_run() -> dict[str, JudgeCallVerdict]:
        answers = await asyncio.gather(*(judge(case) for case in fixture.cases))
        return {case.id: answer for case, answer in zip(fixture.cases, answers, strict=True)}

    return list(await asyncio.gather(*(one_run() for _ in range(runs))))


def _throttled_in_runs(answers: RunAnswers) -> list[str]:
    return [case for run in answers for case, answer in run.items() if answer.throttled]


async def _gate(
    session: JudgeSession, runs: CaseRuns, run_throttled: list[str]
) -> tuple[JudgeGateResult, RetestAnswers]:
    baseline = session.baseline
    mismatches = (
        judge_condition_mismatches(baseline.conditions, session.conditions) if baseline else []
    ) + _throttle_mismatches(run_throttled)
    retests: RetestAnswers = {}
    if baseline is not None and _paired(session) and not mismatches:
        retests = await retest_flips(_retest_context(session), baseline, runs)
        # A throttled retest reads as reproduced, so it would turn the gate red.
        mismatches = _throttle_mismatches(run_throttled + _throttled_in_retests(retests))
    gate_input = _gate_input(session, runs, _observations(retests))
    return decide_judge_gate(replace(gate_input, mismatches=mismatches)), retests


def _throttle_mismatches(throttled: list[str]) -> list[str]:
    if not throttled:
        return []
    return [
        f"{len(throttled)} judgment(s) throttled by the model provider past every retry:"
        " the run cannot be compared"
    ]


def _throttled_in_retests(retests: RetestAnswers) -> list[str]:
    return [case for case, answers in retests.items() for answer in answers if answer.throttled]


def _observations(retests: RetestAnswers) -> dict[str, list[Observation]]:
    return {
        case: [Observation.of(answer.verdict) for answer in answers]
        for case, answers in retests.items()
    }


def _gate_input(
    session: JudgeSession, runs: CaseRuns, observations: dict[str, list[Observation]]
) -> JudgeGateInput:
    return JudgeGateInput(
        mode=GateMode.PAIRED if _paired(session) else GateMode.FLOORS_ONLY,
        runs=runs,
        ground_truth=session.ground_truth,
        baseline=session.baseline,
        retests={
            case: reproductions(retests, session.ground_truth[case])
            for case, retests in observations.items()
        },
        declared=session.declarations.keys,
    )


def _paired(session: JudgeSession) -> bool:
    """No baseline, an unconfirmed one or --no-baseline: the floors alone (ADR 025)."""
    baseline = session.baseline
    return baseline is not None and baseline.status == BaselineStatus.CONFIRMED


def _retest_context(session: JudgeSession) -> RetestContext:
    return RetestContext(
        judge=session.judge,
        ground_truth=session.ground_truth,
        declared=session.declarations.keys,
        cases=session.fixture.cases,
        announce=session.harness.on_retests,
    )


def _exit_code(session: JudgeSession, gate: JudgeGateResult, refused: list[str]) -> int:
    if refused:
        return NOT_COMPARABLE_EXIT
    if session.tree is not None:
        return 0
    return gate.outcome.exit_code
