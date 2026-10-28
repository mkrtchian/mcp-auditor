from datetime import date

from evals.nuisance_results import NuisanceRunStatus, NuisanceServerResult


def a_server_result(
    server_package: str = "npm:@acme/files",
    *,
    split_flaw: str | None = "CVE-2025-0001",
    split_disclosure_date: date | None = date(2026, 1, 1),
    runs: int = 3,
    flagged_runs: int = 0,
    split_flagged_runs: int | None = None,
    incomplete_unflagged_runs: int = 0,
) -> NuisanceServerResult:
    split_flagged = flagged_runs if split_flagged_runs is None else split_flagged_runs
    first_incomplete = runs - incomplete_unflagged_runs
    statuses = tuple(
        NuisanceRunStatus(
            flagged=index < flagged_runs,
            split_flagged=index < split_flagged,
            incomplete=index >= flagged_runs and index >= first_incomplete,
            raw_fail_count=1 if index < flagged_runs else 0,
            non_protocol_lines=0,
            lost_connection_responses=0,
            miss_causes=[],
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
