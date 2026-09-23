import subprocess
from dataclasses import dataclass
from typing import NoReturn

from pydantic import ValidationError

from evals import eval_display as display
from evals.baseline import (
    Baseline,
    BaselineConditions,
    BaselineStatus,
    FixtureConditions,
    condition_mismatches,
    fingerprint_ground_truth,
    fingerprint_source,
    load_baseline,
)
from evals.gate_verdict import GateMode
from evals.honeypots import HONEYPOTS, MERGED_GROUND_TRUTH, REPO_ROOT
from mcp_auditor.config import Settings, load_settings

BASELINE_PATH = REPO_ROOT / "evals" / "baselines" / "honeypot_e2e.json"
NOT_COMPARABLE_EXIT = 3


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


def open_session(options: EvalOptions) -> EvalSession:
    """Exits 3 on anything that would make the run not comparable or its recording refused."""
    if options.record_baseline and options.ungated:
        refuse(
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
    )
    reasons = _pre_run_refusals(session)
    if reasons:
        refuse("Refused before any LLM call.", reasons)
    return session


def refuse(title: str, reasons: list[str]) -> NoReturn:
    display.print_refusal(title, reasons)
    raise SystemExit(NOT_COMPARABLE_EXIT)


def _load_committed_baseline() -> Baseline | None:
    try:
        return load_baseline(BASELINE_PATH)
    except ValidationError as error:
        reason = f"{BASELINE_PATH} is not a valid baseline: {error}"
        refuse("Refused before any LLM call.", [reason])


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
        reasons += _recording_preconditions(session.baseline)
    return reasons


def _recording_preconditions(baseline: Baseline | None) -> list[str]:
    reasons: list[str] = []
    if git("status", "--porcelain", "--untracked-files=no"):
        reasons.append("the git tree has tracked modifications: record from a clean tree")
    if baseline is not None and _exploratory_at_another_commit(baseline):
        reasons.append(
            f"the exploratory baseline was recorded at {baseline.commit}: confirm it at "
            "that commit, or delete it in a commit of its own"
        )
    return reasons


def _exploratory_at_another_commit(baseline: Baseline) -> bool:
    exploratory = baseline.status == BaselineStatus.EXPLORATORY
    return exploratory and git("rev-parse", "HEAD") != baseline.commit


def git(*args: str) -> str:
    completed = subprocess.run(
        ["git", *args], cwd=REPO_ROOT, capture_output=True, text=True, check=True
    )
    return completed.stdout.strip()
