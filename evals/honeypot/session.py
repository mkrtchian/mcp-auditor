"""The session of one honeypot suite run, fixed before any LLM call: its conditions, the
committed baseline, the gate mode, the declarations and, when it records, the tree."""

from dataclasses import dataclass, field
from pathlib import Path

from pydantic import ValidationError

from evals.baseline import (
    Baseline,
    BaselineConditions,
    BaselineStatus,
    FixtureConditions,
    baseline_integrity,
    fingerprint_ground_truth,
    fingerprint_source,
    load_baseline,
)
from evals.declared_flips import (
    ActiveDeclarations,
    Instrument,
    active_declarations,
    declaration_problems,
)
from evals.eval_session import (
    RECORD_WITHOUT_BASELINE,
    RECORDING_REFUSED,
    REFUSED_BEFORE_ANY_LLM_CALL,
    Refused,
    TreeState,
    WorkingTree,
    declarations_of_head,
    recording_tree_refusals,
)
from evals.gate_outcome import GateMode
from evals.ground_truth import GroundTruth, cell_key
from evals.honeypots import HONEYPOTS, MERGED_GROUND_TRUTH
from evals.model_conditions import ModelConditions
from evals.recording import condition_refusals, rescore_refusals, unconfirmed_commit_refusal
from evals.repository import REPO_ROOT
from mcp_auditor.config import Settings

BASELINE_PATH = REPO_ROOT / "evals" / "baselines" / "honeypot.json"
DEFAULT_RUNS = 3
DEFAULT_BUDGET = 10
DEFAULT_CONCURRENCY = 9


@dataclass(frozen=True)
class HoneypotOptions:
    settings: Settings
    runs: int
    budget: int
    report: str
    record_baseline: bool
    no_baseline: bool
    concurrency: int


@dataclass(frozen=True)
class HoneypotSession:
    """Fixed before any LLM call. `baseline` is None under --no-baseline, whatever the file holds.

    The session records a baseline exactly when it holds a `tree`.
    """

    settings: Settings
    conditions: BaselineConditions
    baseline: Baseline | None
    mode: GateMode
    tree: TreeState | None
    declarations: ActiveDeclarations = field(default_factory=ActiveDeclarations)


def open_session(
    options: HoneypotOptions, working_tree: WorkingTree, baseline_path: Path
) -> HoneypotSession:
    """Raises Refused on anything that makes the run not comparable or its recording refused."""
    if options.record_baseline and options.no_baseline:
        raise Refused(RECORDING_REFUSED, [RECORD_WITHOUT_BASELINE])
    baseline = None if options.no_baseline else _load_committed_baseline(baseline_path)
    entries, dirty = declarations_of_head(Instrument.HONEYPOT, working_tree)
    session = HoneypotSession(
        settings=options.settings,
        conditions=_conditions_or_refused(options),
        baseline=baseline,
        mode=select_mode(baseline, options.no_baseline),
        tree=working_tree.read_tree() if options.record_baseline else None,
        declarations=active_declarations(entries, dirty),
    )
    reasons = pre_run_refusals(session, MERGED_GROUND_TRUTH)
    reasons += declaration_problems(entries, {cell_key(cell) for cell in MERGED_GROUND_TRUTH})
    if reasons:
        raise Refused(REFUSED_BEFORE_ANY_LLM_CALL, reasons)
    return session


def _conditions_or_refused(options: HoneypotOptions) -> BaselineConditions:
    try:
        return candidate_conditions(options)
    except ValueError as error:
        raise Refused(REFUSED_BEFORE_ANY_LLM_CALL, [str(error)]) from error


def _load_committed_baseline(path: Path) -> Baseline | None:
    try:
        baseline = load_baseline(path)
    except ValidationError as error:
        reason = f"{path} is not a valid baseline: {error}"
        raise Refused(REFUSED_BEFORE_ANY_LLM_CALL, [reason]) from error
    if baseline is None:
        return None
    problems = baseline_integrity(baseline, MERGED_GROUND_TRUTH)
    if problems:
        raise Refused(REFUSED_BEFORE_ANY_LLM_CALL, problems)
    return baseline


def candidate_conditions(options: HoneypotOptions) -> BaselineConditions:
    return BaselineConditions(
        runs=options.runs,
        budget=options.budget,
        **ModelConditions.of(options.settings).model_dump(),
        ground_truth_fingerprint=fingerprint_ground_truth(MERGED_GROUND_TRUTH),
        fixtures={
            honeypot.name: FixtureConditions(
                source_fingerprint=fingerprint_source(honeypot.server.read_text()),
                chain_budget=honeypot.chain_budget,
                max_chain_steps=honeypot.max_chain_steps,
            )
            for honeypot in HONEYPOTS
        },
    )


def select_mode(baseline: Baseline | None, no_baseline: bool) -> GateMode:
    if no_baseline:
        return GateMode.FLOORS_ONLY
    if baseline is None:
        return GateMode.LEGACY_THRESHOLDS
    if baseline.status == BaselineStatus.UNCONFIRMED:
        return GateMode.FLOORS_ONLY
    return GateMode.PAIRED


def pre_run_refusals(session: HoneypotSession, ground_truth: GroundTruth) -> list[str]:
    """What the file, the labels and the tree already decide, before three paid runs."""
    reasons: list[str] = []
    if session.baseline:
        reasons += condition_refusals(session.baseline, session.conditions)
        reasons += rescore_refusals(session.baseline, ground_truth)
    if session.tree is not None:
        reasons += _recording_refusals(session, session.tree)
    return reasons


def _recording_refusals(session: HoneypotSession, tree: TreeState) -> list[str]:
    reasons = recording_tree_refusals(ci_condition_mismatches(session.conditions), tree)
    if session.baseline:
        reasons += unconfirmed_commit_refusal(session.baseline, tree.commit)
    return reasons


def ci_condition_mismatches(conditions: BaselineConditions) -> list[str]:
    """CI passes no --runs, --budget nor MCP_AUDITOR_* override, so it runs at the defaults."""
    expected = {
        "runs": DEFAULT_RUNS,
        "budget": DEFAULT_BUDGET,
        **ModelConditions.of(Settings.model_construct()).model_dump(),
    }
    actual = conditions.model_dump()
    return [
        f"{field}: CI runs {value}, this run {actual[field]}"
        for field, value in expected.items()
        if actual[field] != value
    ]
