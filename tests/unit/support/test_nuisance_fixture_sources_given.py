from evals.fixture_provenance import StandInOutput, StandInRecord
from evals.holdout_census import load_census
from evals.nuisance_admission import ADMISSION_PATH, AdmittedServer, load_admission
from evals.nuisance_admission_records import SeedRecord
from evals.nuisance_commands import WALK_RECORD_PATH
from evals.nuisance_walk_record import load_walk_record
from evals.run_census import CENSUS_PATH


def admitted_servers() -> list[AdmittedServer]:
    if not ADMISSION_PATH.exists():
        return []
    census = load_census(CENSUS_PATH)
    return list(load_admission(ADMISSION_PATH, load_walk_record(WALK_RECORD_PATH, census)).servers)


def a_server_seeding_with_the_pin(server: AdmittedServer, pin: str) -> AdmittedServer:
    seed = SeedRecord(item="/seed.txt", kind="published_sample", citation="README", pin=pin)
    return server.model_copy(update={"seeds": [seed]})


def a_server_with_a_stand_in(server: AdmittedServer, file: str, request: str) -> AdmittedServer:
    output = StandInOutput(request=request, source="software_sources", citation="API reference")
    stand_in = StandInRecord(
        replaces="a fictional backend", reason="needs a device", file=file, outputs=[output]
    )
    return server.model_copy(update={"stand_ins": [stand_in]})
