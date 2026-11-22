from datetime import date

from evals.cve.holdout_statistic import Side
from evals.cve.nuisance.statistic import SideStatistic, split_by_side
from tests.unit.nuisance.support.nuisance_report_runs import a_server_result

RUN_CUTOFF = date(2026, 5, 18)
_PRE_DATE = date(2026, 1, 1)
_POST_DATE = date(2026, 12, 1)


def sides_of(
    count: int, *, pre_flagged: int, post_flagged: int = 0, post_incomplete_unflagged: int = 0
) -> tuple[SideStatistic, SideStatistic]:
    """The pre-cutoff and post-cutoff sides of `count` servers each, split around RUN_CUTOFF."""
    pre = [
        a_server_result(f"PRE{i}", split_disclosure_date=_PRE_DATE, flagged_runs=pre_flagged)
        for i in range(count)
    ]
    post = [
        a_server_result(
            f"POST{i}",
            split_disclosure_date=_POST_DATE,
            flagged_runs=post_flagged,
            incomplete_unflagged_runs=post_incomplete_unflagged,
        )
        for i in range(count)
    ]
    split = split_by_side(pre + post, RUN_CUTOFF)
    return split[Side.PRE_CUTOFF], split[Side.POST_CUTOFF]
