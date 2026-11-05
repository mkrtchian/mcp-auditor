from evals.fixture_provenance import StandInOutput, StandInRecord
from evals.nuisance_admission import AdmittedServer
from evals.nuisance_admission_records import SeedRecord
from tests.unit.support.test_nuisance_committed_admission_given import the_committed_admission


def admitted_servers() -> list[AdmittedServer]:
    return list(the_committed_admission().servers)


def a_server_seeding_with_the_pin(server: AdmittedServer, pin: str) -> AdmittedServer:
    seed = SeedRecord(item="/seed.txt", kind="published_sample", citation="README", pin=pin)
    return server.model_copy(update={"seeds": [seed]})


def a_server_with_a_stand_in(server: AdmittedServer, file: str, request: str) -> AdmittedServer:
    output = StandInOutput(request=request, source="software_sources", citation="API reference")
    stand_in = StandInRecord(
        replaces="a fictional backend", reason="needs a device", file=file, outputs=[output]
    )
    return server.model_copy(update={"stand_ins": [stand_in]})
