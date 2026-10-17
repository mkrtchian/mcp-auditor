"""The value objects of one gated run of the judge isolation eval: its options, its injected
harness, the session fixed before any judge call and the result it produces."""

from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from evals.declared_flips import ActiveDeclarations, DeclaredFlip
from evals.eval_session import TreeState
from evals.gate import Observation
from evals.judge_baseline import JudgeBaseline, JudgeConditions
from evals.judge_fixture import JudgeFixture
from evals.judge_gate import CaseRuns, JudgeGateResult
from evals.judge_replay import JudgeCall
from mcp_auditor.config import Settings
from mcp_auditor.domain.models import EvalVerdict


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
    on_replays: Callable[[int], None]


@dataclass(frozen=True)
class JudgeSession:
    """Fixed before any judge call. `baseline` is None under --ungated, and `tree` is set
    exactly when the run records. `judge` is the harness's, bounded to the concurrency."""

    harness: JudgeHarness
    judge: JudgeCall
    fixture: JudgeFixture
    ground_truth: dict[str, EvalVerdict]
    conditions: JudgeConditions
    baseline: JudgeBaseline | None
    tree: TreeState | None
    declarations: ActiveDeclarations


@dataclass(frozen=True)
class JudgeSessionResult:
    """`baseline` is the one the run read, None without one or under --ungated."""

    conditions: JudgeConditions
    runs: CaseRuns
    gate: JudgeGateResult
    baseline: JudgeBaseline | None
    replay_observations: dict[str, list[Observation]]
    declarations: ActiveDeclarations
    written: JudgeBaseline | None
    recording_refused: list[str]
    exit_code: int
