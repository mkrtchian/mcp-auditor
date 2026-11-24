"""The nuisance holdout run orchestrator: audit every admitted server on its patched image at one
commit under the run conditions of a detection holdout run, keep no per-case trace, and assemble the
run result.

The counterpart of `evals.cve.detection.holdout_run.run_holdout_targets`. The servers are passed
in, so the tests hand it crafted ones. The heavy I/O is grouped in `NuisanceDeps`, faked by the
unit tests and built by `holdout_run_command.default_deps`. The vet is `vetting`'s, the container
hygiene `containers`', the per-server assembly `assembly`'s, the retry policy `audit`'s, the status
line printed as each run finishes `holdout_run_status`'s.
"""

import dataclasses
from collections.abc import Callable, Coroutine, Sequence
from dataclasses import dataclass
from typing import Any, Protocol

from evals.cve.census.draw_order import DrawEntry
from evals.cve.detection.baseline import grammar_fingerprint
from evals.cve.holdout_conditions import (
    HOLDOUT_TEST_BUDGET,
    HoldoutConditions,
    run_model_ids,
)
from evals.cve.nuisance import images as nuisance_images
from evals.cve.nuisance.admission.admission import AdmittedServer
from evals.cve.nuisance.assembly import assemble_server
from evals.cve.nuisance.audit import DroppedRun, NuisanceAudit
from evals.cve.nuisance.benign_call import BenignCallCheck
from evals.cve.nuisance.containers import rebuilt_run_images, server_services
from evals.cve.nuisance.counter import counter_fingerprint
from evals.cve.nuisance.fingerprint import nuisance_fixture_fingerprint
from evals.cve.nuisance.holdout_run_status import Audit, announcing
from evals.cve.nuisance.holdout_servers import RunPopulation
from evals.cve.nuisance.results import (
    DROPPED_RUN_REASONS,
    NotRunServer,
    NuisanceHoldoutRunResult,
    NuisanceServerResult,
)
from evals.cve.nuisance.solo import first_failure_then_alone, played_alone
from evals.cve.nuisance.vetting import drop_failing_servers
from evals.cve.run_files import RunInterrupted
from evals.cve.run_images import ContainerSweep
from evals.cve.run_interruption import sibling_runs
from evals.eval_session import Refused, TreeState
from evals.model_conditions import ModelConditions
from evals.tracing import TRACING_ON, tracing_enabled
from mcp_auditor.config import Settings

NUISANCE_RUNS = 2  # set in docs/nuisance-suite-log.md, a --runs flag lowers it
NUISANCE_HOLDOUT_RUN_REFUSED = "nuisance holdout run refused"


@dataclass(frozen=True)
class NuisanceDeps:
    audit: Audit
    benign_call: BenignCallCheck
    rebuild: Callable[[Sequence[str]], None]
    image_ids: Callable[[Sequence[str]], dict[str, str]]
    backend_image_ids: Callable[[Sequence[str]], dict[str, str]]
    read_tree: Callable[[], TreeState]
    clock: Callable[[], str]  # ISO timestamp for recorded_at
    announce_audits: Callable[[int], None]
    announce_run: Callable[[str], None]
    throttled_requests: Callable[[], int]
    sweep: ContainerSweep
    check_networks: Callable[[], None]


@dataclass(frozen=True)
class RunProvenance:
    """The commits of the files that decided the run's population. Provenance, never a condition:
    no baseline, gate or comparison reads it."""

    census_commit: str
    walk_record_commit: str
    admission_commit: str


@dataclass(frozen=True)
class NuisanceHoldoutRunInputs:
    population: RunPopulation
    draw_order: Sequence[DrawEntry]
    conditions: HoldoutConditions
    settings: Settings
    provenance: RunProvenance
    runs: int
    concurrency: int

    @property
    def model_ids(self) -> list[str]:
        return run_model_ids(self.settings)


class RunOrchestrator(Protocol):
    def __call__(
        self, inputs: NuisanceHoldoutRunInputs, /, *, deps: NuisanceDeps
    ) -> Coroutine[Any, Any, NuisanceHoldoutRunResult]: ...


async def run_nuisance(
    inputs: NuisanceHoldoutRunInputs, *, deps: NuisanceDeps
) -> NuisanceHoldoutRunResult:
    refuse_tracing()
    inputs.conditions.require_ready(inputs.model_ids)
    tree = deps.read_tree()
    _refuse_dirty_tree(tree)
    with rebuilt_run_images(inputs.population.audited, deps, NUISANCE_HOLDOUT_RUN_REFUSED):
        return await _run_surviving(inputs, deps, tree)


async def _run_surviving(
    inputs: NuisanceHoldoutRunInputs, deps: NuisanceDeps, tree: TreeState
) -> NuisanceHoldoutRunResult:
    vetted = await drop_failing_servers(inputs.population.audited, deps.benign_call, deps.sweep)
    assembled, dropped, failure = await _run_all(vetted.surviving, deps, inputs)
    all_not_run = [*vetted.not_run, *dropped]
    if failure is not None:
        partial = _assemble_run(inputs, deps, assembled, all_not_run, tree)
        raise RunInterrupted(
            dataclasses.replace(partial, partial=True, second_pass=vetted.second_pass), failure
        )
    if not assembled:
        raise Refused(
            NUISANCE_HOLDOUT_RUN_REFUSED,
            [
                "no server survived the vet and the runs",
                *(entry.reason for entry in all_not_run),
            ],
        )
    result = _assemble_run(inputs, deps, assembled, all_not_run, tree)
    return dataclasses.replace(result, second_pass=vetted.second_pass)


def refuse_tracing() -> None:
    if tracing_enabled():
        raise Refused(
            NUISANCE_HOLDOUT_RUN_REFUSED,
            [f"{TRACING_ON}; a nuisance holdout run keeps no trace"],
        )


def _refuse_dirty_tree(tree: TreeState) -> None:
    if tree.dirty:
        raise Refused(
            NUISANCE_HOLDOUT_RUN_REFUSED,
            ["the git tree is dirty: a nuisance holdout run publishes from a clean tree"],
        )


async def _run_all(
    surviving: Sequence[AdmittedServer], deps: NuisanceDeps, inputs: NuisanceHoldoutRunInputs
) -> tuple[
    list[tuple[AdmittedServer, NuisanceServerResult]], list[NotRunServer], BaseException | None
]:
    """The finished servers, assembled or dropped, and the exception that stopped the run, if
    any: a first exception out of a server's runs cancels every server still in flight."""
    total = len(surviving) * inputs.runs
    deps.announce_audits(total)
    audit = announcing(deps.audit, deps.announce_run, total)
    finished, failure = await first_failure_then_alone(
        surviving, lambda server: _run_server(server, audit, inputs.runs)
    )
    prices = inputs.conditions.audit_prices(
        inputs.settings.resolve_model(), inputs.settings.resolve_judge_model()
    )
    assembled: list[tuple[AdmittedServer, NuisanceServerResult]] = []
    dropped: list[NotRunServer] = []
    for server, outcomes in finished:
        if isinstance(outcomes, DroppedRun):
            reason = DROPPED_RUN_REASONS[outcomes.cause]
            dropped.append(NotRunServer(server.server_package, reason, outcomes.cause))
        else:
            result = assemble_server(server, outcomes, inputs.draw_order, prices)
            assembled.append((server, result))
    return assembled, dropped, failure


async def _run_server(
    server: AdmittedServer, audit: Audit, runs: int
) -> list[NuisanceAudit] | DroppedRun:
    if played_alone(server):
        outcomes = [await audit(server) for _ in range(runs)]
    else:
        outcomes = await sibling_runs(runs, lambda: audit(server))
    causes = {outcome.cause for outcome in outcomes if isinstance(outcome, DroppedRun)}
    if causes:
        return DroppedRun.from_causes(causes)
    return [outcome for outcome in outcomes if not isinstance(outcome, DroppedRun)]


def _assemble_run(
    inputs: NuisanceHoldoutRunInputs,
    deps: NuisanceDeps,
    assembled: Sequence[tuple[AdmittedServer, NuisanceServerResult]],
    not_run: list[NotRunServer],
    tree: TreeState,
) -> NuisanceHoldoutRunResult:
    servers = [server for server, _ in assembled]
    results = [result for _, result in assembled]
    return NuisanceHoldoutRunResult(
        runs=inputs.runs,
        budget=HOLDOUT_TEST_BUDGET,
        **ModelConditions.of(inputs.settings).model_dump(),
        cutoffs={model_id: inputs.conditions.cutoffs[model_id] for model_id in inputs.model_ids},
        chain_budget=inputs.conditions.chain_budget,
        max_chain_steps=inputs.conditions.max_chain_steps,
        tool_call_timeout=inputs.conditions.tool_call_timeout,
        grammar_fingerprint=grammar_fingerprint(),
        counter_fingerprint=counter_fingerprint(),
        fixture_fingerprints={s.server_package: nuisance_fixture_fingerprint(s) for s in servers},
        commit=tree.commit,
        census_commit=inputs.provenance.census_commit,
        walk_record_commit=inputs.provenance.walk_record_commit,
        admission_commit=inputs.provenance.admission_commit,
        image_ids={
            **deps.image_ids(server_services(servers)),
            **deps.backend_image_ids(nuisance_images.backend_images(servers)),
        },
        recorded_at=deps.clock(),
        servers=results,
        not_run=not_run,
        exits=list(inputs.population.exits),
        incomplete_run_count=sum(result.incomplete_runs for result in results),
        total_cost=sum(result.run_cost for result in results),
        prices_as_of=inputs.conditions.prices_as_of,
        concurrency=inputs.concurrency,
        throttled_requests=deps.throttled_requests(),
        pending_admission=list(inputs.population.pending),
    )
