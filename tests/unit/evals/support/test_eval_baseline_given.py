from evals.baseline import Baseline, BaselineStatus, RecordingRef
from tests.unit.evals.support.honeypot_baselines import RECORDED_COMMIT, ObservationRuns, a_baseline


def a_confirmation(runs: ObservationRuns) -> Baseline:
    first = RecordingRef(commit=RECORDED_COMMIT, recorded_at="2026-09-23T09:00:00+00:00")
    return a_baseline(status=BaselineStatus.CONFIRMED, runs=runs).model_copy(
        update={"confirms": first}
    )
