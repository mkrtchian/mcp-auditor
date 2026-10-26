"""The nuisance run orchestrator: audit every admitted server on its patched image at one commit
under the holdout's run conditions, keep no per-case trace, and assemble the run result.

A sibling of `holdout_run.run_holdout`. The servers are passed in, so the tests hand it crafted
ones. The heavy I/O is grouped in `NuisanceDeps`, faked by the unit tests and built from the live
settings by `default_deps`. The per-server assembly is `nuisance_assembly`'s, the retry policy
`nuisance_audit`'s.
"""

import asyncio
import functools
import os
from collections.abc import Awaitable, Callable, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime

from evals import nuisance_images
from evals.concurrency import bounded, entered_in_thread
from evals.cve_audit import RunOverrides, build_auditor
from evals.cve_baseline import grammar_fingerprint, image_ids
from evals.cve_environments import TOOL_CALL_TIMEOUT, connect
from evals.eval_runs import tracing_enabled
from evals.eval_session import Refused, TreeState, read_tree
from evals.holdout_conditions import HoldoutConditions
from evals.holdout_draw import DrawEntry
from evals.holdout_run import HOLDOUT_BUDGET, rebuild_images
from evals.nuisance_admission import AdmittedServer
from evals.nuisance_assembly import assemble_server
from evals.nuisance_audit import (
    DroppedRun,
    audit_once,
    benign_call_failure,
    nuisance_audit,
    nuisance_environment,
)
from evals.nuisance_counter import counter_fingerprint
from evals.nuisance_images import nuisance_fixture_fingerprint
from evals.nuisance_population import RunPopulation
from evals.nuisance_results import (
    DROPPED_RUN_REASONS,
    NotRunCause,
    NotRunServer,
    NuisanceRunResult,
    NuisanceServerResult,
)
from evals.probe_candidates import Prices
from mcp_auditor.config import Settings
from mcp_auditor.domain.models import AuditReport

NUISANCE_RUNS = 3  # the log sets it before the first real run, a --runs flag lowers it
NUISANCE_CONCURRENCY = 6
# The budget is the holdout's HOLDOUT_BUDGET: the rule reads the figure beside the holdout run,
# whose budget is a constant, not a flag (holdout-rule.md:227), so no budget of its own here.

type Audit = Callable[[AdmittedServer], Awaitable[AuditReport | DroppedRun]]


@dataclass(frozen=True)
class NuisanceDeps:
    audit: Audit
    benign_call: Callable[[AdmittedServer], Awaitable[str | None]]  # its failure reason, or None
    rebuild: Callable[[Sequence[str]], None]
    image_ids: Callable[[Sequence[str]], dict[str, str]]
    backend_image_ids: Callable[[Sequence[str]], dict[str, str]]
    read_tree: Callable[[], TreeState]
    clock: Callable[[], str]  # ISO timestamp for recorded_at


@dataclass(frozen=True)
class _RunContext:
    conditions: HoldoutConditions
    settings: Settings
    draw_order: Sequence[DrawEntry]
    model_ids: list[str]
    runs: int
    census_commit: str


async def run_nuisance(
    population: RunPopulation,
    draw_order: Sequence[DrawEntry],
    conditions: HoldoutConditions,
    settings: Settings,
    census_commit: str,
    *,
    runs: int = NUISANCE_RUNS,
    concurrency: int = NUISANCE_CONCURRENCY,
    deps: NuisanceDeps | None = None,
) -> NuisanceRunResult:
    _refuse_tracing()
    model_ids = list(dict.fromkeys([settings.resolve_model(), settings.resolve_judge_model()]))
    conditions.require_ready(model_ids)
    ctx = _RunContext(conditions, settings, draw_order, model_ids, runs, census_commit)
    overrides = _overrides(conditions)
    deps = deps or default_deps(overrides, concurrency)
    tree = deps.read_tree()
    _refuse_dirty_tree(tree)
    deps.rebuild(_services(population.audited))
    not_run, surviving = await _vet_all(population.audited, deps)
    assembled, dropped = await _run_all(surviving, deps, ctx)
    all_not_run = [*not_run, *dropped]
    if not assembled:
        raise Refused(
            "nuisance run refused",
            [
                "no server survived the pre-run check and the runs",
                *(entry.reason for entry in all_not_run),
            ],
        )
    return _assemble_run(ctx, deps, population, assembled, all_not_run, tree)


def _refuse_tracing() -> None:
    if tracing_enabled():
        raise Refused(
            "nuisance run refused",
            ["LANGSMITH_TRACING or LANGCHAIN_TRACING_V2 is set; a nuisance run keeps no trace"],
        )


def _refuse_dirty_tree(tree: TreeState) -> None:
    if tree.dirty:
        raise Refused(
            "nuisance run refused",
            ["the git tree is dirty: a nuisance run publishes from a clean tree"],
        )


def _overrides(conditions: HoldoutConditions) -> RunOverrides:
    chain, steps = conditions.chain_budget, conditions.max_chain_steps
    timeout = conditions.tool_call_timeout
    assert chain is not None and steps is not None and timeout is not None  # require_ready passed
    return RunOverrides(chain, steps, timeout)


def default_deps(overrides: RunOverrides, concurrency: int) -> NuisanceDeps:
    auditor = build_auditor(HOLDOUT_BUDGET)
    timeout = overrides.tool_call_timeout or TOOL_CALL_TIMEOUT

    async def audit(server: AdmittedServer) -> AuditReport | DroppedRun:
        return await nuisance_audit(server, lambda: audit_once(server, auditor, overrides))

    return NuisanceDeps(
        bounded(audit, concurrency),
        bounded(functools.partial(benign_call, timeout=timeout), concurrency),
        rebuild_images,
        functools.partial(image_ids, tag=nuisance_images.image_tag),
        nuisance_images.backend_image_ids,
        read_tree,
        lambda: datetime.now(UTC).isoformat(),
    )


async def benign_call(server: AdmittedServer, timeout: int) -> str | None:
    """The benign call's failure reason, or None when it answers."""
    try:
        with open(os.devnull, "w") as devnull:
            async with (
                entered_in_thread(nuisance_environment(server)) as launch,
                connect(launch, devnull, tool_call_timeout=timeout) as client,
            ):
                return await benign_call_failure(server, client)
    except Exception as exc:
        return f"failed to connect for the benign call: {exc}"


async def _vet_all(
    servers: Sequence[AdmittedServer], deps: NuisanceDeps
) -> tuple[list[NotRunServer], list[AdmittedServer]]:
    reasons = await asyncio.gather(*(deps.benign_call(server) for server in servers))
    paired = list(zip(servers, reasons, strict=True))
    not_run = [
        NotRunServer(server.server_package, reason, NotRunCause.BENIGN_CALL_FAILED)
        for server, reason in paired
        if reason is not None
    ]
    return not_run, [server for server, reason in paired if reason is None]


async def _run_all(
    surviving: Sequence[AdmittedServer], deps: NuisanceDeps, ctx: _RunContext
) -> tuple[list[tuple[AdmittedServer, NuisanceServerResult]], list[NotRunServer]]:
    runs_per = await asyncio.gather(
        *(_run_server(server, deps.audit, ctx.runs) for server in surviving)
    )
    assembled: list[tuple[AdmittedServer, NuisanceServerResult]] = []
    dropped: list[NotRunServer] = []
    for server, outcomes in zip(surviving, runs_per, strict=True):
        if isinstance(outcomes, DroppedRun):
            reason = DROPPED_RUN_REASONS[outcomes.cause]
            dropped.append(NotRunServer(server.server_package, reason, outcomes.cause))
        else:
            result = assemble_server(server, outcomes, ctx.draw_order, _prices(ctx))
            assembled.append((server, result))
    return assembled, dropped


async def _run_server(
    server: AdmittedServer, audit: Audit, runs: int
) -> list[AuditReport] | DroppedRun:
    outcomes = await asyncio.gather(*(audit(server) for _ in range(runs)))
    causes = {outcome.cause for outcome in outcomes if isinstance(outcome, DroppedRun)}
    if NotRunCause.THROTTLED in causes:
        return DroppedRun(NotRunCause.THROTTLED)
    if causes:
        return DroppedRun(NotRunCause.LAUNCH_FAILURE)
    return [outcome for outcome in outcomes if not isinstance(outcome, DroppedRun)]


def _prices(ctx: _RunContext) -> tuple[Prices, Prices]:
    prices = ctx.conditions.prices
    return prices[ctx.settings.resolve_model()], prices[ctx.settings.resolve_judge_model()]


def _assemble_run(
    ctx: _RunContext,
    deps: NuisanceDeps,
    population: RunPopulation,
    assembled: Sequence[tuple[AdmittedServer, NuisanceServerResult]],
    not_run: list[NotRunServer],
    tree: TreeState,
) -> NuisanceRunResult:
    settings = ctx.settings
    model, judge_model = settings.resolve_model(), settings.resolve_judge_model()
    servers = [server for server, _ in assembled]
    results = [result for _, result in assembled]
    return NuisanceRunResult(
        runs=ctx.runs,
        budget=HOLDOUT_BUDGET,
        provider=settings.provider,
        model=model,
        judge_model=judge_model,
        reasoning=settings.resolve_reasoning(model),
        judge_reasoning=settings.resolve_reasoning(judge_model),
        cutoffs={model_id: ctx.conditions.cutoffs[model_id] for model_id in ctx.model_ids},
        chain_budget=ctx.conditions.chain_budget,
        max_chain_steps=ctx.conditions.max_chain_steps,
        tool_call_timeout=ctx.conditions.tool_call_timeout,
        grammar_fingerprint=grammar_fingerprint(),
        counter_fingerprint=counter_fingerprint(),
        fixture_fingerprints={s.server_package: nuisance_fixture_fingerprint(s) for s in servers},
        commit=tree.commit,
        census_commit=ctx.census_commit,
        image_ids={
            **deps.image_ids(_services(servers)),
            **deps.backend_image_ids(_backend_images(servers)),
        },
        recorded_at=deps.clock(),
        servers=results,
        not_run=not_run,
        outside_figure=list(population.outside_figure),
        incomplete_run_count=sum(result.incomplete_runs for result in results),
        total_cost=sum(result.run_cost for result in results),
        prices_as_of=ctx.conditions.prices_as_of,
    )


def _services(servers: Sequence[AdmittedServer]) -> list[str]:
    return list(dict.fromkeys(server.service for server in servers))


def _backend_images(servers: Sequence[AdmittedServer]) -> list[str]:
    return list(
        dict.fromkeys(server.backend.image for server in servers if server.backend is not None)
    )
