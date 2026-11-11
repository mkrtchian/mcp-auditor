import pytest

from evals.cve.census.census import load_census
from evals.cve.nuisance.commands import WALK_RECORD_PATH
from evals.cve.nuisance.fingerprint import nuisance_fixture_fingerprint
from evals.cve.nuisance.walk_record import load_walk_record
from evals.nuisance_admission import ADMISSION_PATH, AdmittedServer, load_admission
from evals.run_census import CENSUS_PATH
from tests.unit.support.test_nuisance_committed_admission_given import the_committed_admission


def test_the_committed_admission_loads():
    load_admission(ADMISSION_PATH, load_walk_record(WALK_RECORD_PATH, load_census(CENSUS_PATH)))


@pytest.mark.parametrize(
    "server", the_committed_admission().servers, ids=lambda server: server.service
)
def test_each_admitted_server_fingerprints_from_committed_files(server: AdmittedServer):
    nuisance_fixture_fingerprint(server)
