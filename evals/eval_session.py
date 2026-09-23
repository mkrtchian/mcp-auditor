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
from mcp_auditor.config import Settings, load_settings

BASELINE_PATH = REPO_ROOT / "evals" / "baselines" / "honeypot_e2e.json"
DEFAULT_RUNS = 3
DEFAULT_BUDGET = 10
NOT_COMPARABLE_EXIT = 3
CRASHED_EXIT = 4


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
class EvalSession:
    """Fixed before any LLM call. `baseline` is None under --ungated, whatever the file holds."""

    settings: Settings
    conditions: BaselineConditions
    baseline: Baseline | None
    mode: GateMode
    record: bool
    commit: str | None


def open_session(options: EvalOptions) -> EvalSession:
    """Raises Refused on anything that makes the run not comparable or its recording refused."""
    if options.record_baseline and options.ungated:
        raise Refused(
            "Recording refused.",
            ["--record-baseline cannot run --ungated: a baseline records the conditions it gates"],
        )
    settings = load_settings()
    baseline = None if options.ungated else _load_committed_baseline()
    session = EvalSession(
        settings=settings,
        conditions=_candidate_conditions(settings, options),
        baseline=baseline,
        mode=_select_mode(baseline, options.ungated),
        record=options.record_baseline,
        commit=git("rev-parse", "HEAD") if options.record_baseline else None,
    )
    reasons = _pre_run_refusals(session)
    if reasons:
        raise Refused("Refused before any LLM call.", reasons)
    return session


def ci_condition_mismatches(conditions: BaselineConditions) -> list[str]:
    """CI passes no --runs, --budget nor MCP_AUDITOR_* override, so it runs at the defaults."""
    defaults = Settings.model_construct()
    expected = {
        "runs": DEFAULT_RUNS,
        "budget": DEFAULT_BUDGET,
        "provider": defaults.provider,
        "model": defaults.resolve_model(),
        "judge_model": defaults.resolve_judge_model(),
    }
    actual = conditions.model_dump()
    return [
        f"{field}: CI runs {value}, this run {actual[field]}"
        for field, value in expected.items()
        if actual[field] != value
    ]


def tree_drift(session: EvalSession) -> list[str]:
    """What changed in the checkout while the runs of a recording went on."""
    reasons: list[str] = []
    if git("status", "--porcelain", "--untracked-files=no"):
        reasons.append("tracked files changed during the runs: record again from a clean tree")
    if git("rev-parse", "HEAD") != session.commit:
        reasons.append(f"HEAD moved from {session.commit} during the runs: record again")
    return reasons


def _load_committed_baseline() -> Baseline | None:
    try:
        baseline = load_baseline(BASELINE_PATH)
    except ValidationError as error:
        reason = f"{BASELINE_PATH} is not a valid baseline: {error}"
        raise Refused("Refused before any LLM call.", [reason]) from error
    if baseline is None:
        return None
    problems = baseline_integrity(baseline, MERGED_GROUND_TRUTH)
    if problems:
        raise Refused("Refused before any LLM call.", problems)
    return baseline


def _candidate_conditions(settings: Settings, options: EvalOptions) -> BaselineConditions:
    return BaselineConditions(
        runs=options.runs,
        budget=options.budget,
        provider=settings.provider,
        model=settings.resolve_model(),
        judge_model=settings.resolve_judge_model(),
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


def _select_mode(baseline: Baseline | None, ungated: bool) -> GateMode:
    if ungated:
        return GateMode.FLOORS_ONLY
    if baseline is None:
        return GateMode.LEGACY_THRESHOLDS
    if baseline.status == BaselineStatus.EXPLORATORY:
        return GateMode.FLOORS_ONLY
    return GateMode.PAIRED


def _pre_run_refusals(session: EvalSession) -> list[str]:
    reasons: list[str] = []
    if session.baseline:
        reasons += condition_mismatches(session.baseline.conditions, session.conditions)
    if session.record:
        reasons += _recording_preconditions(session)
    return reasons


def _recording_preconditions(session: EvalSession) -> list[str]:
    reasons = [
        f"a baseline records the conditions CI runs at, {mismatch}"
        for mismatch in ci_condition_mismatches(session.conditions)
    ]
    if git("status", "--porcelain", "--untracked-files=no"):
        reasons.append("the git tree has tracked modifications: record from a clean tree")
    baseline = session.baseline
    if baseline and _exploratory_at_another_commit(baseline, session.commit):
        reasons.append(
            f"the exploratory baseline was recorded at {baseline.commit}: confirm it at "
            "that commit, or delete it in a commit of its own"
        )
    return reasons


def _exploratory_at_another_commit(baseline: Baseline, commit: str | None) -> bool:
    return baseline.status == BaselineStatus.EXPLORATORY and baseline.commit != commit


def git(*args: str) -> str:
    try:
        completed = subprocess.run(
            ["git", *args], cwd=REPO_ROOT, capture_output=True, text=True, check=True
        )
    except (subprocess.CalledProcessError, FileNotFoundError) as error:
        reason = f"git {' '.join(args)} failed: record from a git checkout"
        raise Refused("Recording refused.", [reason]) from error
    return completed.stdout.strip()
