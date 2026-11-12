import pytest

import tests.unit.support.test_nuisance_fixture_sources_then as then
from evals.cve.nuisance.admission import AdmittedServer
from tests.unit.support.test_nuisance_committed_admission_given import the_committed_admission

ADMITTED = the_committed_admission().servers


@pytest.mark.parametrize("server", ADMITTED, ids=lambda server: server.service)
def test_every_fingerprinted_dockerfile_copies_in_nothing_the_fingerprint_misses(
    server: AdmittedServer,
):
    then.every_dockerfile_copies_nothing_unsourced(server)


@pytest.mark.parametrize("server", ADMITTED, ids=lambda server: server.service)
def test_every_seed_pin_is_in_the_fingerprinted_content(server: AdmittedServer):
    then.every_seed_pin_is_fingerprinted(server)


@pytest.mark.parametrize("server", ADMITTED, ids=lambda server: server.service)
def test_every_stand_in_is_a_fingerprinted_file_holding_its_requests(server: AdmittedServer):
    then.every_stand_in_is_a_fingerprinted_file_holding_its_requests(server)
