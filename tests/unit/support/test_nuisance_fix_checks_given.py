from evals.cve.docker_paths import image_dockerfile
from evals.cve.images import dockerfile_instructions
from evals.cve.kit.client import KitTool
from evals.cve.kit.driver import Exchange, KitExchangeLog
from evals.cve.kit.fix_check import FixCheckExploit, FixCheckFixture
from evals.cve.nuisance.admission import AdmittedServer, FlawRecord
from evals.cve.nuisance.counting import flaw_counted_tools, flaw_tools
from tests.fakes import FakeKitClient
from tests.unit.support.test_nuisance_committed_admission_given import the_committed_admission


def flaw_record(fixture: FixCheckFixture) -> FlawRecord:
    return next(
        flaw
        for server in the_committed_admission().servers
        for flaw in server.flaws
        if flaw.flaw == fixture.flaw
    )


def admitted_server(fixture: FixCheckFixture) -> AdmittedServer:
    return next(
        server
        for server in the_committed_admission().servers
        if any(flaw.flaw == fixture.flaw for flaw in server.flaws)
    )


def reached_tools(fixture: FixCheckFixture) -> frozenset[str]:
    return flaw_tools(flaw_record(fixture))


def counted_tools(fixture: FixCheckFixture) -> frozenset[str]:
    return flaw_counted_tools(flaw_record(fixture))


async def recorded(fixture: FixCheckFixture, *calls: FixCheckExploit) -> list[Exchange]:
    # A server exposing exactly the tools the admission lists under the flaw, each discoverable by
    # the witness-id description an exploit matches on. A static exploit calls its hard-coded name
    # and ignores the list; a dynamic one (contextforge slugifies the registered name, so it
    # resolves the name at run time via list_tools) then resolves a listed tool instead of raising.
    tools = [
        KitTool(name=tool, description=f"seeded {fixture.witness.id}", input_schema={})
        for tool in reached_tools(fixture)
    ]
    exchange_log = KitExchangeLog(FakeKitClient(tools))
    places = {fixture.witness.id: fixture.witness}
    for call in calls:
        await call(places, exchange_log)
    return exchange_log.exchanges


def build_arguments(service: str) -> set[str]:
    instructions = dockerfile_instructions(image_dockerfile(service))
    return {line for line in instructions if line.split()[0].upper() == "ARG"}
