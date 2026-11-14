from datetime import date

from evals.cve.holdout_statistic import Side
from evals.cve.nuisance.results import NuisanceRunStatus, NuisanceServerResult
from evals.cve.nuisance.statistic import SideStatistic, split_by_side

RUN_CUTOFF = date(2026, 5, 18)
_PRE_DATE = date(2026, 1, 1)
_POST_DATE = date(2026, 12, 1)


def a_server_result(
    server_package: str = "npm:@acme/files",
    *,
    split_flaw: str | None = "CVE-2025-0001",
    split_disclosure_date: date | None = date(2026, 1, 1),
    runs: int = 3,
    flagged_runs: int = 0,
    split_flagged_runs: int | None = None,
    incomplete_unflagged_runs: int = 0,
    declared_function_fail_runs: int = 0,
) -> NuisanceServerResult:
    split_flagged = flagged_runs if split_flagged_runs is None else split_flagged_runs
    first_incomplete = runs - incomplete_unflagged_runs
    statuses = tuple(
        NuisanceRunStatus(
            flagged=index < flagged_runs,
            split_flagged=index < split_flagged,
            incomplete=index >= flagged_runs and index >= first_incomplete,
            raw_fail_count=(index < flagged_runs) + (index < declared_function_fail_runs),
            declared_function_fail_count=1 if index < declared_function_fail_runs else 0,
            non_protocol_lines=0,
            lost_connection_responses=0,
            missed_call_causes=[],
        )
        for index in range(runs)
    )
    return NuisanceServerResult(
        server_package=server_package,
        split_flaw=split_flaw,
        split_disclosure_date=split_disclosure_date,
        statuses=statuses,
        counted_tools_count=1,
        tools_count=4,
        run_cost=0.0,
    )


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
