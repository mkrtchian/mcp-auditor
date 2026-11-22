from collections.abc import Sequence
from datetime import date

from evals.cve.holdout_conditions import Cutoff
from evals.cve.nuisance.results import (
    NotRunServer,
    NuisanceHoldoutRunResult,
    NuisanceHoldoutRunStatus,
    NuisanceServerResult,
    ServerExit,
)

LUNA_CUTOFF = Cutoff(
    date=date(2026, 5, 18), type="training", source="https://example.test/luna", note=None
)
RECORDED_AT = "2026-10-22T09:30:00+00:00"
RUNS = 3


def a_run(
    servers: Sequence[NuisanceServerResult],
    *,
    not_run: Sequence[NotRunServer] = (),
    exits: Sequence[ServerExit] = (),
    cutoffs: dict[str, Cutoff] | None = None,
    throttled_requests: int = 0,
    concurrency: int = 6,
    second_pass: dict[str, str] | None = None,
    pending_admission: Sequence[str] = (),
) -> NuisanceHoldoutRunResult:
    return NuisanceHoldoutRunResult(
        runs=RUNS,
        budget=10,
        provider="openai",
        model="gpt-6-luna",
        judge_model="gpt-6-luna",
        reasoning="none",
        judge_reasoning="none",
        cutoffs={"gpt-6-luna": LUNA_CUTOFF} if cutoffs is None else cutoffs,
        chain_budget=3,
        max_chain_steps=5,
        tool_call_timeout=30,
        grammar_fingerprint="grammar-abc",
        counter_fingerprint="counter-abc",
        fixture_fingerprints={"npm:@acme/files": "fa"},
        commit="deadbeef",
        census_commit="cafe1234",
        walk_record_commit="beef5678",
        admission_commit="feed4321",
        image_ids={"patched": "sha256:1"},
        recorded_at=RECORDED_AT,
        servers=tuple(servers),
        not_run=tuple(not_run),
        exits=tuple(exits),
        incomplete_run_count=sum(server.incomplete_runs for server in servers),
        total_cost=0.06,
        prices_as_of=date(2026, 10, 15),
        concurrency=concurrency,
        throttled_requests=throttled_requests,
        second_pass=second_pass or {},
        pending_admission=tuple(pending_admission),
    )


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
        NuisanceHoldoutRunStatus(
            flagged=index < flagged_runs,
            split_flagged=index < split_flagged,
            incomplete=index >= flagged_runs and index >= first_incomplete,
            raw_fail_count=(index < flagged_runs) + (index < declared_function_fail_runs),
            declared_function_fail_count=1 if index < declared_function_fail_runs else 0,
            non_protocol_lines=0,
            lost_connection_responses=0,
            relaunches=0,
            unsent_calls=0,
            cut_responses=0,
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
