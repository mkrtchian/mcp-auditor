from evals.cve.detection.gate import TargetCandidate
from evals.cve.grammar import TargetStatus
from tests.unit.detection.support.detection_baselines import DETECTED, FIXTURE, FLAW_ID


def a_candidate(
    runs: list[TargetStatus] | None = None,
    fixture: str = FIXTURE,
    completed: bool = True,
    depends_on_unchecked: bool = False,
) -> TargetCandidate:
    return TargetCandidate(
        flaw_id=FLAW_ID,
        fixture_fingerprint=fixture,
        runs=runs if runs is not None else [DETECTED] * 3,
        completed=completed,
        depends_on_unchecked=depends_on_unchecked,
    )
