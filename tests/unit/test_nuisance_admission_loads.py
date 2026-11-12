import pytest

from evals.cve.census.census import load_census
from evals.cve.nuisance.admission import ADMISSION_PATH, AdmittedServer, load_admission
from evals.cve.nuisance.commands import WALK_RECORD_PATH
from evals.cve.nuisance.fingerprint import nuisance_fixture_fingerprint
from evals.cve.nuisance.holdout_calibration_copies import stale_holdout_calibration_copies
from evals.cve.nuisance.unrecorded import unrecorded_fields
from evals.cve.nuisance.walk_record import load_walk_record
from evals.run_census import CENSUS_PATH
from tests.unit.support.test_nuisance_committed_admission_given import (
    current_copy_fingerprints,
    the_committed_admission,
)


def test_the_committed_admission_loads():
    load_admission(ADMISSION_PATH, load_walk_record(WALK_RECORD_PATH, load_census(CENSUS_PATH)))


def test_every_holdout_calibration_copy_is_recorded_at_its_targets_current_fingerprint():
    servers = the_committed_admission().servers

    assert stale_holdout_calibration_copies(servers, current_copy_fingerprints()) == []


def test_the_committed_admission_records_every_field_the_rule_adds():
    assert unrecorded_fields(the_committed_admission().servers) == []


@pytest.mark.parametrize(
    "server", the_committed_admission().servers, ids=lambda server: server.service
)
def test_each_admitted_server_fingerprints_from_committed_files(server: AdmittedServer):
    nuisance_fixture_fingerprint(server)
