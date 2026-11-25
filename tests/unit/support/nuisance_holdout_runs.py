from collections.abc import Awaitable, Callable, Mapping, Sequence
from datetime import date

import tests.unit.support.grammar_inputs as grammar
import tests.unit.support.nuisance_admissions as admissions
from evals.cve.census.draw_order import DrawEntry
from evals.cve.grammar import FlawClass
from evals.cve.nuisance.admission.admission import AdmittedServer, FlawRecord
from evals.cve.nuisance.audit import DroppedRun, NuisanceAudit
from evals.cve.nuisance.holdout_run import (
    NuisanceDeps,
    NuisanceHoldoutRunInputs,
    RunProvenance,
    run_nuisance,
)
from evals.cve.nuisance.holdout_servers import RunPopulation
from evals.cve.nuisance.results import NuisanceHoldoutRunResult, ServerExit
from evals.cve.run_images import ContainerSweep
from evals.cve.server_health import NO_INCIDENTS, ServerHealth
from evals.eval_session import TreeState
from mcp_auditor.domain.model_calls import MissedCallCause, MissedModelCall, ModelCallKind
from mcp_auditor.domain.models import AuditReport, ProviderUsage
from tests.fakes import FakeContainerSweep, ScriptedBenignCall
from tests.unit.support.holdout_run_conditions import SETTINGS, ready_conditions
from tests.unit.support.unreached import unreached

COUNTED_TOOL = f"{admissions.FIRST_FLAW}_read"
RECORDED_AT = "2026-10-22T00:00:00+00:00"
DEFAULT_RUNS = 3

type Outcome = NuisanceAudit | DroppedRun
type Audit = Callable[[AdmittedServer], Awaitable[Outcome]]


def a_server(
    package: str = admissions.SERVER_PACKAGE,
    *,
    # A service whose Dockerfile exists, since the run fingerprints the server's fixture.
    service: str = "filesystem-patched",
    flaws: list[FlawRecord] | None = None,
) -> AdmittedServer:
    the_flaws = (
        flaws
        if flaws is not None
        else [
            admissions.a_flaw_record(
                admissions.FIRST_FLAW, FlawClass.READ_OUTSIDE_SCOPE, admissions.PATCHED_VERSION
            )
        ]
    )
    server = admissions.a_server(the_flaws)
    return server.model_copy(update={"server_package": package, "service": service})


def scripted(outcomes_by_package: Mapping[str, Sequence[Outcome]]) -> Audit:
    scripts = {package: list(outcomes) for package, outcomes in outcomes_by_package.items()}

    async def audit(server: AdmittedServer) -> Outcome:
        return scripts[server.server_package].pop(0)

    return audit


def clean_audits() -> list[Outcome]:
    return [an_audit(False) for _ in range(DEFAULT_RUNS)]


def an_audit(
    flagged: bool,
    *,
    missed: MissedCallCause | None = None,
    provider: ProviderUsage | None = None,
    judge: ProviderUsage | None = None,
    health: ServerHealth = NO_INCIDENTS,
) -> NuisanceAudit:
    return NuisanceAudit(a_report(flagged, missed=missed, provider=provider, judge=judge), health)


def a_report(
    flagged: bool,
    *,
    missed: MissedCallCause | None = None,
    provider: ProviderUsage | None = None,
    judge: ProviderUsage | None = None,
) -> AuditReport:
    """One tool report on the counted tool: a FAIL in a category of its class when flagged, a
    PASS otherwise, and a missed model call of the given cause."""
    verdict = grammar.FAIL if flagged else grammar.PASS
    tool_report = grammar.a_tool_report(COUNTED_TOOL, cases=[grammar.a_case(verdict=verdict)])
    missed_calls = (
        []
        if missed is None
        else [
            MissedModelCall(
                tool_name=COUNTED_TOOL, kind=ModelCallKind.JUDGMENT, cause=missed, detail=""
            )
        ]
    )
    return AuditReport(
        server_command="test",
        tool_reports=[tool_report],
        provider_usage=provider or ProviderUsage(),
        judge_usage=judge or ProviderUsage(),
        missed_model_calls=missed_calls,
    )


def deps_auditing(
    audit: Audit,
    *,
    benign_call: Mapping[str, str | Sequence[str | None] | None] | None = None,
    throttled: int = 0,
    containers: FakeContainerSweep | None = None,
    announced: list[str] | None = None,
) -> NuisanceDeps:
    """`benign_call` scripts each server's failure reasons as `ScriptedBenignCall` reads them.
    `announced` collects the status line of each finished run."""
    lines = announced if announced is not None else []
    docker = containers or FakeContainerSweep()
    return NuisanceDeps(
        audit=audit,
        benign_call=ScriptedBenignCall(benign_call),
        rebuild=lambda services: None,
        image_ids=lambda names: {name: f"sha256:{name}" for name in names},
        backend_image_ids=lambda tags: {tag: f"sha256:{tag}" for tag in tags},
        read_tree=lambda: TreeState(commit="c0ffee", dirty=False),
        clock=lambda: RECORDED_AT,
        announce_audits=lambda audits: None,
        announce_run=lines.append,
        throttled_requests=lambda: throttled,
        sweep=docker.sweep,
        check_networks=lambda: None,
    )


def deps_reaching_nothing() -> NuisanceDeps:
    return NuisanceDeps(
        audit=unreached("the audit"),
        benign_call=unreached("the benign call"),
        rebuild=unreached("the image rebuild"),
        image_ids=unreached("the image id lookup"),
        backend_image_ids=unreached("the backend image id lookup"),
        read_tree=unreached("the tree read"),
        clock=unreached("the clock"),
        announce_audits=unreached("the audit announcement"),
        announce_run=unreached("the run announcement"),
        throttled_requests=unreached("the throttled request count"),
        sweep=ContainerSweep(unreached("the container listing"), unreached("a container removal")),
        check_networks=lambda: None,
    )


async def run(
    servers: Sequence[AdmittedServer],
    deps: NuisanceDeps,
    *,
    exits: Sequence[ServerExit] = (),
    pending: Sequence[str] = (),
    runs: int = DEFAULT_RUNS,
    concurrency: int = 6,
) -> NuisanceHoldoutRunResult:
    """The draw order holds the first flaw alone, disclosed on 2026-01-01, before the cutoff of
    the run conditions."""
    inputs = NuisanceHoldoutRunInputs(
        population=RunPopulation(servers, exits, pending),
        draw_order=draw_entries((admissions.FIRST_FLAW, date(2026, 1, 1))),
        conditions=ready_conditions(),
        settings=SETTINGS,
        provenance=RunProvenance(
            census_commit="cafe", walk_record_commit="beef", admission_commit="f00d"
        ),
        runs=runs,
        concurrency=concurrency,
    )
    return await run_nuisance(inputs, deps=deps)


def draw_entries(*entries: tuple[str, date]) -> list[DrawEntry]:
    return [
        DrawEntry(digest=f"{index:064x}", identifier=identifier, disclosure_date=disclosed)
        for index, (identifier, disclosed) in enumerate(entries)
    ]
