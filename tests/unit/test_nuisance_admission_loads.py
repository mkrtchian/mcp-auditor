import pytest

from evals.cve_planting import SymbolicUser
from evals.holdout_census import load_census
from evals.nuisance_admission import ADMISSION_PATH, AdmittedServer, load_admission
from evals.nuisance_commands import WALK_RECORD_PATH
from evals.nuisance_fingerprint import nuisance_fixture_fingerprint
from evals.nuisance_walk_record import load_walk_record
from evals.run_census import CENSUS_PATH
from tests.unit.support.test_nuisance_committed_admission_given import the_committed_admission


def test_the_committed_admission_loads():
    load_admission(ADMISSION_PATH, load_walk_record(WALK_RECORD_PATH, load_census(CENSUS_PATH)))


@pytest.mark.parametrize(
    "server", the_committed_admission().servers, ids=lambda server: server.service
)
def test_each_admitted_server_fingerprints_from_committed_files(server: AdmittedServer):
    nuisance_fixture_fingerprint(server)


def test_no_admitted_server_runs_as_the_host_user():
    servers = the_committed_admission().servers

    assert [s.server_package for s in servers if s.host.user is SymbolicUser.HOST] == []
