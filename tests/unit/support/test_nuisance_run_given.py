import asyncio
from collections.abc import AsyncGenerator, Awaitable, Callable, Generator, Mapping, Sequence
from contextlib import asynccontextmanager, contextmanager
from datetime import date
from typing import IO

import pytest

import tests.unit.support.test_cve_grammar_given as grammar
import tests.unit.support.test_nuisance_admission_given as admission
import tests.unit.support.test_nuisance_counter_given as counter
from evals import nuisance_run
from evals.cve_environments import Launch
from evals.cve_grammar import MechanismClass
from evals.eval_session import TreeState
from evals.holdout_conditions import Cutoff, HoldoutConditions
from evals.holdout_draw import DrawEntry
from evals.nuisance_admission import AdmittedServer, FlawRecord
from evals.nuisance_audit import DroppedRun, NuisanceAudit
from evals.nuisance_population import RunPopulation
from evals.nuisance_results import FigureExit, NuisanceRunResult
from evals.nuisance_run import NuisanceDeps, run_nuisance
from evals.probe_candidates import Prices
from evals.server_health import NO_INCIDENTS, ServerHealth
from mcp_auditor.config import Settings
from mcp_auditor.domain.models import (
    AuditReport,
    AuditStep,
    MissCause,
    MissedStep,
    ProviderUsage,
    ToolResponse,
)
from mcp_auditor.domain.ports import MCPClientPort
from tests.fakes.mcp_client import FakeMCPClient
from tests.unit.support.test_holdout_run_given import RunningContainers

FIRST_FLAW = admission.FIRST_FLAW
SECOND_FLAW = admission.SECOND_FLAW
COUNTED_TOOL = f"{FIRST_FLAW}_read"
LUNA_PRICE = Prices(input=0.10, cached_input=0.01, output=0.50)
SETTINGS = Settings(provider="openai", model="gpt-6-luna", judge_model="", reasoning="none")
RECORDED_AT = "2026-10-22T00:00:00+00:00"

type Outcome = NuisanceAudit | DroppedRun
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


def an_audit(
    flagged: bool,
    *,
    missed: MissCause | None = None,
    provider: ProviderUsage | None = None,
    judge: ProviderUsage | None = None,
    health: ServerHealth = NO_INCIDENTS,
) -> NuisanceAudit:
    return NuisanceAudit(a_report(flagged, missed=missed, provider=provider, judge=judge), health)


def scripted(outcomes_by_package: Mapping[str, list[Outcome]]) -> Audit:
    scripts = {package: list(outcomes) for package, outcomes in outcomes_by_package.items()}

    async def audit(server: AdmittedServer) -> Outcome:
        return scripts[server.server_package].pop(0)

    return audit


class InterruptingAudit:
    """The finished server's runs answer at once. The failing server's first run raises `error`
    once the finished server is done, and every other run waits until it is cancelled."""

    def __init__(self, finished: str, failing: str, error: Exception) -> None:
        self.cancelled: list[str] = []
        self._finished, self._failing, self._error = finished, failing, error
        self._reports: list[Outcome] = [an_audit(False) for _ in range(3)]
        self._finished_done = asyncio.Event()
        self._failing_calls = 0

    async def __call__(self, server: AdmittedServer) -> Outcome:
        if server.server_package == self._finished:
            return self._report()
        if server.server_package == self._failing:
            self._failing_calls += 1
            if self._failing_calls == 1:
                await self._finished_done.wait()
                await asyncio.sleep(0.01)  # lets the finished server's task complete
                raise self._error
        return await self._until_cancelled(server)

    def _report(self) -> Outcome:
        outcome = self._reports.pop(0)
        if not self._reports:
            self._finished_done.set()
        return outcome

    async def _until_cancelled(self, server: AdmittedServer) -> Outcome:
        try:
            await asyncio.Event().wait()
        except asyncio.CancelledError:
            self.cancelled.append(server.server_package)
            raise
        raise AssertionError("a run that never ends completed")


def deps_auditing(
    audit: Audit,
    *,
    benign_call: dict[str, str | None] | None = None,
    throttled: int = 0,
    containers: RunningContainers | None = None,
) -> NuisanceDeps:
    reasons = benign_call or {}
    docker = containers or RunningContainers()

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
        announce_audits=lambda audits: None,
        throttled_requests=lambda: throttled,
        running_containers=docker.running,
        remove_containers=docker.remove,
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
        throttled_requests,
        running_containers,
        remove_containers,
    )


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
    concurrency: int = 6,
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
        concurrency=concurrency,
        deps=deps,
    )


class FlakyLaunches:
    """Stands in for the server's launch and connection: the first `failing` connections fail,
    the last of them on a timeout, and the next ones answer every benign call with `answer`, then
    fail their teardown when `teardown_fails`."""

    def __init__(self, failing: int, answer: ToolResponse, teardown_fails: bool) -> None:
        self.launches = 0
        self._failing = failing
        self._answer = answer
        self._teardown_fails = teardown_fails

    @contextmanager
    def environment(self, _server: AdmittedServer) -> Generator[Launch]:
        self.launches += 1
        yield Launch("docker", [])

    @asynccontextmanager
    async def connect(
        self, _launch: Launch, _stderr: IO[str], *, tool_call_timeout: int
    ) -> AsyncGenerator[MCPClientPort]:
        if self.launches == self._failing:
            raise TimeoutError("initialize timed out")
        if self.launches < self._failing:
            raise ConnectionError("Connection closed")
        yield FakeMCPClient([], {COUNTED_TOOL: self._answer})
        if self._teardown_fails:
            raise OSError("container removal failed")


def launches_failing(
    monkeypatch: pytest.MonkeyPatch,
    failing: int,
    answer: ToolResponse | None = None,
    teardown_fails: bool = False,
) -> FlakyLaunches:
    flaky = FlakyLaunches(failing, answer or ToolResponse(content="ok"), teardown_fails)
    monkeypatch.setattr(nuisance_run, "nuisance_environment", flaky.environment)
    monkeypatch.setattr(nuisance_run, "connect", flaky.connect)
    return flaky
