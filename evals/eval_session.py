import subprocess
from dataclasses import dataclass

from pydantic import ValidationError

from evals.baseline import (
    Baseline,
    BaselineConditions,
    BaselineStatus,
    FixtureConditions,
    baseline_integrity,
    condition_mismatches,
    fingerprint_ground_truth,
    fingerprint_source,
    load_baseline,
)
from evals.gate_verdict import GateMode
from evals.honeypots import HONEYPOTS, MERGED_GROUND_TRUTH, REPO_ROOT
from evals.recording import exploratory_commit_refusal
from mcp_auditor.config import Settings, load_settings

BASELINE_PATH = REPO_ROOT / "evals" / "baselines" / "honeypot_e2e.json"
DEFAULT_RUNS = 3
DEFAULT_BUDGET = 10
RECORDING_REFUSED = "Recording refused."
REFUSED_BEFORE_ANY_LLM_CALL = "Refused before any LLM call."


class Refused(Exception):
    def __init__(self, title: str, reasons: list[str]) -> None:
        super().__init__(title, reasons)
        self.title = title
        self.reasons = reasons


@dataclass(frozen=True)
class EvalOptions:
    runs: int
    budget: int
    report: str
    record_baseline: bool
    ungated: bool


@dataclass(frozen=True)
class TreeState:
    commit: str
    dirty: bool


@dataclass(frozen=True)
class EvalSession:
    """Fixed before any LLM call. `baseline` is None under --ungated, whatever the file holds.

    The session records a baseline exactly when it holds a `tree`.
    """

    settings: Settings
    conditions: BaselineConditions
    baseline: Baseline | None
    mode: GateMode
    tree: TreeState | None


def open_session(options: EvalOptions) -> EvalSession:
    """Raises Refused on anything that makes the run not comparable or its recording refused."""
    if options.record_baseline and options.ungated:
        raise Refused(
            RECORDING_REFUSED,
            ["--record-baseline cannot run --ungated: a baseline records the conditions it gates"],
        )
    settings = load_settings()
    baseline = None if options.ungated else _load_committed_baseline()
    session = EvalSession(
        settings=settings,
        conditions=_conditions_or_refused(settings, options),
        baseline=baseline,
        mode=select_mode(baseline, options.ungated),
        tree=read_tree() if options.record_baseline else None,
    )
    reasons = pre_run_refusals(session)
    if reasons:
        raise Refused(REFUSED_BEFORE_ANY_LLM_CALL, reasons)
    return session


def _conditions_or_refused(settings: Settings, options: EvalOptions) -> BaselineConditions:
    try:
        return candidate_conditions(settings, options)
    except ValueError as error:
        raise Refused(REFUSED_BEFORE_ANY_LLM_CALL, [str(error)]) from error


def _load_committed_baseline() -> Baseline | None:
    try:
        baseline = load_baseline(BASELINE_PATH)
    except ValidationError as error:
        reason = f"{BASELINE_PATH} is not a valid baseline: {error}"
        raise Refused(REFUSED_BEFORE_ANY_LLM_CALL, [reason]) from error
    if baseline is None:
        return None
    problems = baseline_integrity(baseline, MERGED_GROUND_TRUTH)
    if problems:
        raise Refused(REFUSED_BEFORE_ANY_LLM_CALL, problems)
    return baseline


def candidate_conditions(settings: Settings, options: EvalOptions) -> BaselineConditions:
    return BaselineConditions(
        runs=options.runs,
        budget=options.budget,
        provider=settings.provider,
        model=settings.resolve_model(),
        judge_model=settings.resolve_judge_model(),
        reasoning=settings.resolve_reasoning(settings.resolve_model()),
        judge_reasoning=settings.resolve_reasoning(settings.resolve_judge_model()),
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


def select_mode(baseline: Baseline | None, ungated: bool) -> GateMode:
    if ungated:
        return GateMode.FLOORS_ONLY
    if baseline is None:
        return GateMode.LEGACY_THRESHOLDS
    if baseline.status == BaselineStatus.EXPLORATORY:
        return GateMode.FLOORS_ONLY
    return GateMode.PAIRED


def pre_run_refusals(session: EvalSession) -> list[str]:
    reasons: list[str] = []
    if session.baseline:
        reasons += condition_mismatches(session.baseline.conditions, session.conditions)
    if session.tree is not None:
        reasons += _recording_refusals(session, session.tree)
    return reasons


def _recording_refusals(session: EvalSession, tree: TreeState) -> list[str]:
    reasons = [
        f"a baseline records the conditions CI runs at, {mismatch}"
        for mismatch in ci_condition_mismatches(session.conditions)
    ]
    if tree.dirty:
        reasons.append("the git tree has tracked modifications: record from a clean tree")
    if session.baseline:
        reasons += exploratory_commit_refusal(session.baseline, tree.commit)
    return reasons


def ci_condition_mismatches(conditions: BaselineConditions) -> list[str]:
    """CI passes no --runs, --budget nor MCP_AUDITOR_* override, so it runs at the defaults."""
    defaults = Settings.model_construct()
    expected = {
        "runs": DEFAULT_RUNS,
        "budget": DEFAULT_BUDGET,
        "provider": defaults.provider,
        "model": defaults.resolve_model(),
        "judge_model": defaults.resolve_judge_model(),
        "reasoning": defaults.resolve_reasoning(defaults.resolve_model()),
        "judge_reasoning": defaults.resolve_reasoning(defaults.resolve_judge_model()),
    }
    actual = conditions.model_dump()
    return [
        f"{field}: CI runs {value}, this run {actual[field]}"
        for field, value in expected.items()
        if actual[field] != value
    ]


def tree_drift(before: TreeState, after: TreeState) -> list[str]:
    """What changed in the checkout while the runs of a recording went on."""
    reasons: list[str] = []
    if after.dirty:
        reasons.append("tracked files changed during the runs: record again from a clean tree")
    if after.commit != before.commit:
        reasons.append(
            f"HEAD moved from {before.commit} to {after.commit} during the runs: record again"
        )
    return reasons


def baseline_changed(loaded: Baseline | None, current: Baseline | None) -> list[str]:
    if loaded == current:
        return []
    return ["the baseline file changed during the runs: record again"]


def read_tree() -> TreeState:
    return TreeState(
        commit=_git("rev-parse", "HEAD"),
        dirty=bool(_git("status", "--porcelain", "--untracked-files=no")),
    )


def _git(*args: str) -> str:
    try:
        completed = subprocess.run(
            ["git", *args], cwd=REPO_ROOT, capture_output=True, text=True, check=True
        )
    except (subprocess.CalledProcessError, FileNotFoundError) as error:
        reason = f"git {' '.join(args)} failed: run from a git checkout"
        raise Refused("Git unavailable.", [reason]) from error
    return completed.stdout.strip()
