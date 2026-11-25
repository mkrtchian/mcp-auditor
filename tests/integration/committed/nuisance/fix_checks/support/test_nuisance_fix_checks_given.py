from evals.cve.docker_paths import image_dockerfile
from evals.cve.images import dockerfile_instructions
from evals.cve.kit.fix_check import FixCheckFixture
from evals.cve.nuisance.admission.admission import AdmittedServer
from evals.cve.nuisance.counting import flaw_counted_tools
from tests.integration.committed.nuisance.fix_checks.support.recorded_exchanges import flaw_record
from tests.unit.support.committed_nuisance_admission import the_committed_admission


def admitted_server(fixture: FixCheckFixture) -> AdmittedServer:
    return next(
        server
        for server in the_committed_admission().servers
        if any(flaw.flaw == fixture.flaw for flaw in server.flaws)
    )


def counted_tools(fixture: FixCheckFixture) -> frozenset[str]:
    return flaw_counted_tools(flaw_record(fixture))


def build_arguments(service: str) -> set[str]:
    instructions = dockerfile_instructions(image_dockerfile(service))
    return {line for line in instructions if line.split()[0].upper() == "ARG"}
