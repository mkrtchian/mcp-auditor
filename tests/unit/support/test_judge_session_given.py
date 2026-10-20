from collections import Counter
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal

from evals.baseline import BaselineStatus
from evals.declared_flips import DeclaredFlip, Suite
from evals.eval_session import TreeState
from evals.judge_baseline import JudgeBaseline, write_judge_baseline
from evals.judge_fixture import JudgeCase
from evals.judge_session_model import JudgeHarness, JudgeOptions
from mcp_auditor.config import Settings
from mcp_auditor.domain.models import EvalVerdict
from tests.unit.support.test_judge_baseline_given import (
    FAIL_ID,
    PASS_ID,
    RECORDED_COMMIT,
    UNSPECIFIED_ID,
    a_baseline,
    a_ground_truth,
    a_judge_fixture,
    runs_where,
)

__all__ = [
    "FAIL_ID",
    "PASS_ID",
    "RECORDED_COMMIT",
    "UNSPECIFIED_ID",
    "a_baseline",
    "a_judge_fixture",
    "runs_where",
]

FAIL, PASS = EvalVerdict.FAIL, EvalVerdict.PASS
BASE = "0123456789abcdef0123456789abcdef01234567"
THROTTLED_JUDGMENT: Literal["throttled"] = "throttled"

type ScriptedVerdict = EvalVerdict | Literal["throttled"] | None


@dataclass
class ScriptedJudge:
    """Plays each case's script in call order, then judges it correctly. A throttled judgment
    gives no verdict and is recorded, as the composition root's tracking does."""

    scripts: dict[str, list[ScriptedVerdict]] = field(
        default_factory=dict[str, list[ScriptedVerdict]]
    )
    calls: Counter[str] = field(default_factory=Counter[str])
    throttled: list[str] = field(default_factory=list[str])

    async def __call__(self, case: JudgeCase) -> EvalVerdict | None:
        self.calls[case.id] += 1
        script = self.scripts.get(case.id)
        if not script:
            return a_ground_truth().get(case.id, PASS)
        verdict = script.pop(0)
        if verdict == THROTTLED_JUDGMENT:
            self.throttled.append(case.id)
            return None
        return verdict

    def total_calls(self) -> int:
        return sum(self.calls.values())


def a_judge_flipping(case_id: str, *verdicts: ScriptedVerdict) -> ScriptedJudge:
    return ScriptedJudge({case_id: list(verdicts)})


def options(runs: int = 3, record_baseline: bool = False, ungated: bool = False) -> JudgeOptions:
    return JudgeOptions(
        settings=Settings.model_construct(),
        runs=runs,
        record_baseline=record_baseline,
        ungated=ungated,
        concurrency=4,
    )


def a_harness(
    judge: ScriptedJudge,
    baseline_path: Path,
    trees: list[TreeState] | None = None,
    declarations: list[DeclaredFlip] | None = None,
    on_replays: Callable[[int], None] = lambda _: None,
) -> JudgeHarness:
    """`trees` are read in turn, the last one repeated."""
    read = _reader(trees or [a_clean_tree()])
    return JudgeHarness(
        judge=judge,
        baseline_path=baseline_path,
        read_tree=lambda: next(read),
        declarations=lambda: (declarations or [], False),
        clock=lambda: datetime(2026, 9, 28, 14, tzinfo=UTC),
        on_replays=on_replays,
        throttled_judgments=lambda: judge.throttled,
    )


def _reader(trees: list[TreeState]) -> Iterator[TreeState]:
    yield from trees
    while True:
        yield trees[-1]


def a_clean_tree(commit: str = RECORDED_COMMIT) -> TreeState:
    return TreeState(commit=commit, dirty=False)


def a_baseline_file(tmp_path: Path, baseline: JudgeBaseline | None = None) -> Path:
    path = tmp_path / "judge_isolation.json"
    write_judge_baseline(path, baseline or a_baseline())
    return path


def an_exploratory_baseline_file(tmp_path: Path, commit: str = RECORDED_COMMIT) -> Path:
    return a_baseline_file(tmp_path, a_baseline(BaselineStatus.EXPLORATORY, commit=commit))


def a_broken_baseline_file(tmp_path: Path) -> Path:
    path = tmp_path / "judge_isolation.json"
    path.write_text("{not json")
    return path


def a_declaration(case_id: str) -> DeclaredFlip:
    return DeclaredFlip(
        suite=Suite.JUDGE,
        key=case_id,
        mechanism="the judge prompt no longer reads stack traces as leaks",
        base=BASE,
        runs_seen=[],
    )
