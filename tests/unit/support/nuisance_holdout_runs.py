from collections.abc import Awaitable, Callable, Mapping, Sequence
from datetime import date

import tests.unit.support.grammar_inputs as grammar
import tests.unit.support.nuisance_admissions as admissions
from evals.cve.census.draw_order import DrawEntry
from evals.cve.grammar import FlawClass
from evals.cve.holdout_conditions import Cutoff, HoldoutConditions
from evals.cve.nuisance.admission.admission import AdmittedServer, FlawRecord
from evals.cve.nuisance.audit import DroppedRun, NuisanceAudit
from evals.cve.nuisance.holdout_run import NuisanceDeps, RunProvenance, run_nuisance
from evals.cve.nuisance.holdout_servers import RunPopulation
from evals.cve.nuisance.results import NuisanceHoldoutRunResult, ServerExit
from evals.cve.run_images import ContainerSweep
from evals.cve.server_health import NO_INCIDENTS, ServerHealth
from evals.eval_session import TreeState
from evals.pricing import Prices
from mcp_auditor.config import Settings
from mcp_auditor.domain.model_calls import MissedCallCause, MissedModelCall, ModelCallKind
from mcp_auditor.domain.models import AuditReport, ProviderUsage
from tests.fakes import FakeContainerSweep, ScriptedBenignCall

FIRST_FLAW = admissions.FIRST_FLAW
SECOND_FLAW = admissions.SECOND_FLAW
COUNTED_TOOL = f"{FIRST_FLAW}_read"
LUNA_PRICE = Prices(input=0.10, cached_input=0.01, output=0.50)
SETTINGS = Settings(provider="openai", model="gpt-6-luna", judge_model="", reasoning="none")
RECORDED_AT = "2026-10-22T00:00:00+00:00"

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
                FIRST_FLAW, FlawClass.READ_OUTSIDE_SCOPE, admissions.PATCHED_VERSION
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
    steps = (
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
        missed_model_calls=steps,
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
    async def audit(_server: AdmittedServer) -> Outcome:
        raise AssertionError("the audit was reached")

    async def benign_call(_server: AdmittedServer) -> str | None:
        raise AssertionError("the benign call was reached")

    def rebuild(_services: object) -> None:
        raise AssertionError("the image rebuild was reached")

    def image_ids(_names: object) -> dict[str, str]:
        raise AssertionError("the image ids were read")

    def backend_image_ids(_tags: object) -> dict[str, str]:
        raise AssertionError("the backend image ids were read")

    def read_tree() -> TreeState:
        raise AssertionError("read_tree was reached")

    def clock() -> str:
        raise AssertionError("the clock was read")

    def announce_audits(_audits: int) -> None:
        raise AssertionError("the audits were announced")

    def announce_run(_line: str) -> None:
        raise AssertionError("a run was announced")

    def throttled_requests() -> int:
        raise AssertionError("the throttled requests were read")

    def running_containers(_tags: object) -> list[str]:
        raise AssertionError("the running containers were listed")

    def remove_containers(_containers: object) -> None:
        raise AssertionError("a container was removed")

    return NuisanceDeps(
        audit,
        benign_call,
        rebuild,
        image_ids,
        backend_image_ids,
        read_tree,
        clock,
        announce_audits,
        announce_run,
        throttled_requests,
        ContainerSweep(running_containers, remove_containers),
        lambda: None,
    )


async def run(
    servers: Sequence[AdmittedServer],
    deps: NuisanceDeps,
    *,
    draw: Sequence[DrawEntry] | None = None,
    exits: Sequence[ServerExit] = (),
    pending: Sequence[str] = (),
    runs: int = 3,
    concurrency: int = 6,
) -> NuisanceHoldoutRunResult:
    """`draw=None` puts the first flaw in the draw order, disclosed on 2026-01-01."""
    order = draw if draw is not None else draw_entries((FIRST_FLAW, date(2026, 1, 1)))
    return await run_nuisance(
        RunPopulation(servers, exits, pending),
        order,
        conditions(),
        SETTINGS,
        RunProvenance(census_commit="cafe", walk_record_commit="beef", admission_commit="f00d"),
        runs=runs,
        concurrency=concurrency,
        deps=deps,
    )


def conditions() -> HoldoutConditions:
    return HoldoutConditions(
        chain_budget=3,
        max_chain_steps=5,
        tool_call_timeout=30,
        cutoffs={
            "gpt-6-luna": Cutoff(
                date=date(2026, 5, 18), type="training", source="https://example.test", note=None
            )
        },
        prices={"gpt-6-luna": LUNA_PRICE},
        prices_as_of=date(2026, 10, 15),
    )


def draw_entries(*entries: tuple[str, date]) -> list[DrawEntry]:
    return [
        DrawEntry(digest=f"{index:064x}", identifier=identifier, disclosure_date=disclosed)
        for index, (identifier, disclosed) in enumerate(entries)
    ]
