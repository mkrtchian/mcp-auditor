from io import StringIO
from typing import Any

import pytest
from rich.console import Console

import tests.unit.support.test_judge_outcomes_given as outcomes_given
from evals import judge_display
from evals.gate import CellComparison, CellOutcome, FlipCause
from evals.judge_outcomes import CaseOutcomes, case_outcomes
from evals.judge_session import JudgeSessionResult

FLIPPED_ID = outcomes_given.FLIPPED_ID


def a_captured_console(monkeypatch: pytest.MonkeyPatch) -> StringIO:
    buffer = StringIO()
    monkeypatch.setattr(judge_display, "console", Console(file=buffer, width=200))
    return buffer


def a_result_with_a_flip_not_reproduced() -> JudgeSessionResult:
    return outcomes_given.a_result(
        {
            FLIPPED_ID: CellComparison(
                outcome=CellOutcome.FLIP_NOT_REPRODUCED,
                cause=FlipCause.WRONG_VERDICT,
                replays=[True, False, False],
            ),
            outcomes_given.STEADY_ID: CellComparison(outcome=CellOutcome.UNCHANGED),
        },
        replay_observations={FLIPPED_ID: [outcomes_given.F, outcomes_given.P, outcomes_given.P]},
    )


def the_outcomes_of(result: JudgeSessionResult) -> CaseOutcomes:
    return case_outcomes(result, outcomes_given.a_judge_fixture())


def a_report(throttled_requests: int = 0, concurrency: int = 30) -> dict[str, Any]:
    metrics = {
        "precision": 1.0,
        "recall": 1.0,
        "f1": 1.0,
        "confusion_matrix": {"tp": 1, "fp": 0, "tn": 2, "fn": 0},
    }
    return {
        "per_run": [metrics],
        "per_category": {"input_validation": metrics},
        "concurrency": concurrency,
        "throttled_requests": throttled_requests,
    }
