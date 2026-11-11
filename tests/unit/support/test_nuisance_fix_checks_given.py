from evals.cve.images import dockerfile_instructions
from evals.docker_paths import image_dockerfile
from evals.holdout_kit.fix_check import FixCheckExploit, FixCheckTarget
from evals.holdout_kit.kit_client import KitTool
from evals.holdout_kit.kit_driver import Exchange, KitRecorder
from evals.nuisance_admission import AdmittedServer, FlawRecord
from evals.nuisance_counting import flaw_counted_tools, flaw_tools
from tests.fakes import FakeKitClient
from tests.unit.support.test_nuisance_committed_admission_given import the_committed_admission


def flaw_record(target: FixCheckTarget) -> FlawRecord:
    return next(
        flaw
        for server in the_committed_admission().servers
        for flaw in server.flaws
        if flaw.flaw == target.flaw
    )


def admitted_server(target: FixCheckTarget) -> AdmittedServer:
    return next(
        server
        for server in the_committed_admission().servers
        if any(flaw.flaw == target.flaw for flaw in server.flaws)
    )


def reached_tools(target: FixCheckTarget) -> frozenset[str]:
    return flaw_tools(flaw_record(target))


def counted_tools(target: FixCheckTarget) -> frozenset[str]:
    return flaw_counted_tools(flaw_record(target))


async def recorded(target: FixCheckTarget, *calls: FixCheckExploit) -> list[Exchange]:
    # A server exposing exactly the tools the admission lists under the flaw, each discoverable by
    # the witness-id description an exploit matches on. A static exploit calls its hard-coded name
    # and ignores the list; a dynamic one (contextforge slugifies the registered name, so it
    # resolves the name at run time via list_tools) then resolves a listed tool instead of raising.
    tools = [
        KitTool(name=tool, description=f"seeded {target.witness.id}", input_schema={})
        for tool in reached_tools(target)
    ]
    recorder = KitRecorder(FakeKitClient(tools))
    places = {target.witness.id: target.witness}
    for call in calls:
        await call(places, recorder)
    return recorder.exchanges


def build_arguments(service: str) -> set[str]:
    instructions = dockerfile_instructions(image_dockerfile(service))
    return {line for line in instructions if line.split()[0].upper() == "ARG"}
