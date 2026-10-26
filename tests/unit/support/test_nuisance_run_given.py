from collections.abc import Awaitable, Callable, Mapping, Sequence
from datetime import date

import tests.unit.support.test_cve_grammar_given as grammar
import tests.unit.support.test_nuisance_admission_given as admission
import tests.unit.support.test_nuisance_counter_given as counter
from evals.cve_grammar import MechanismClass
from evals.eval_session import TreeState
from evals.holdout_conditions import Cutoff, HoldoutConditions
from evals.holdout_draw import DrawEntry
from evals.nuisance_admission import AdmittedServer, FlawRecord
from evals.nuisance_audit import DroppedRun
from evals.nuisance_population import RunPopulation
from evals.nuisance_results import FigureExit, NuisanceRunResult
from evals.nuisance_run import NuisanceDeps, run_nuisance
from evals.probe_candidates import Prices
from mcp_auditor.config import Settings
from mcp_auditor.domain.models import AuditReport, AuditStep, MissCause, MissedStep, ProviderUsage

FIRST_FLAW = admission.FIRST_FLAW
SECOND_FLAW = admission.SECOND_FLAW
COUNTED_TOOL = f"{FIRST_FLAW}_read"
LUNA_PRICE = Prices(input=0.10, cached_input=0.01, output=0.50)
SETTINGS = Settings(provider="openai", model="gpt-6-luna", judge_model="", reasoning="none")
RECORDED_AT = "2026-10-22T00:00:00+00:00"

type Outcome = AuditReport | DroppedRun
type Audit = Callable[[AdmittedServer], Awaitable[Outcome]]


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


def a_server(
    package: str = admission.SERVER_PACKAGE,
    *,
    # A service whose Dockerfile exists, since the run fingerprints the server's fixture.
    service: str = "filesystem-patched",
    flaws: list[FlawRecord] | None = None,
) -> AdmittedServer:
    the_flaws = (
        flaws
        if flaws is not None
        else [
            admission.a_flaw_record(
                FIRST_FLAW, MechanismClass.READ_OUTSIDE_SCOPE, admission.PATCHED_VERSION
            )
        ]
    )
    server = admission.a_server(the_flaws)
    return server.model_copy(update={"server_package": package, "service": service})


def a_two_flaw_server() -> AdmittedServer:
    return a_server(
        flaws=[
            admission.a_flaw_record(
                FIRST_FLAW, MechanismClass.READ_OUTSIDE_SCOPE, admission.PATCHED_VERSION
            ),
            admission.a_flaw_record(
                SECOND_FLAW, MechanismClass.COMMAND_EXECUTION, admission.PATCHED_VERSION
            ),
        ]
    )


def a_report(
    flagged: bool,
    *,
    missed: MissCause | None = None,
    provider: ProviderUsage | None = None,
    judge: ProviderUsage | None = None,
) -> AuditReport:
    """One tool report on the counted tool: a FAIL in a category of its class when flagged, a
    PASS otherwise, and a missed step of the given cause."""
    verdict = grammar.FAIL if flagged else grammar.PASS
    tool_report = counter.a_tool_report(COUNTED_TOOL, cases=[grammar.a_case(verdict=verdict)])
    steps = (
        []
        if missed is None
        else [MissedStep(tool_name=COUNTED_TOOL, step=AuditStep.JUDGMENT, cause=missed, detail="")]
    )
    return AuditReport(
        target="test",
        tool_reports=[tool_report],
        provider_usage=provider or ProviderUsage(),
        judge_usage=judge or ProviderUsage(),
        missed_steps=steps,
    )


def scripted(outcomes_by_package: Mapping[str, list[Outcome]]) -> Audit:
    scripts = {package: list(outcomes) for package, outcomes in outcomes_by_package.items()}

    async def audit(server: AdmittedServer) -> Outcome:
        return scripts[server.server_package].pop(0)

    return audit


def deps_auditing(
    audit: Audit, *, benign_call: dict[str, str | None] | None = None
) -> NuisanceDeps:
    reasons = benign_call or {}

    async def _benign_call(server: AdmittedServer) -> str | None:
        return reasons.get(server.server_package)

    return NuisanceDeps(
        audit=audit,
        benign_call=_benign_call,
        rebuild=lambda services: None,
        image_ids=lambda names: {name: f"sha256:{name}" for name in names},
        backend_image_ids=lambda tags: {tag: f"sha256:{tag}" for tag in tags},
        read_tree=lambda: TreeState(commit="c0ffee", dirty=False),
        clock=lambda: RECORDED_AT,
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

    return NuisanceDeps(audit, benign_call, rebuild, image_ids, backend_image_ids, read_tree, clock)


def draw_entries(*entries: tuple[str, date]) -> list[DrawEntry]:
    return [
        DrawEntry(digest=f"{index:064x}", identifier=identifier, disclosure_date=disclosed)
        for index, (identifier, disclosed) in enumerate(entries)
    ]


async def run(
    servers: Sequence[AdmittedServer],
    deps: NuisanceDeps,
    *,
    draw: Sequence[DrawEntry] | None = None,
    outside_figure: Sequence[FigureExit] = (),
    runs: int = 3,
) -> NuisanceRunResult:
    """`draw=None` puts the first flaw in the draw order, disclosed on 2026-01-01."""
    order = draw if draw is not None else draw_entries((FIRST_FLAW, date(2026, 1, 1)))
    return await run_nuisance(
        RunPopulation(servers, outside_figure),
        order,
        conditions(),
        SETTINGS,
        census_commit="cafe",
        runs=runs,
        deps=deps,
    )
