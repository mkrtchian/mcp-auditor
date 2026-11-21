import re
from collections import Counter

import pytest

from evals.cve.census.census import load_census
from evals.cve.nuisance.admission.admission import ADMISSION_PATH, AdmittedServer, load_admission
from evals.cve.nuisance.admission.holdout_calibration_copies import stale_holdout_calibration_copies
from evals.cve.nuisance.admission.unrecorded import unrecorded_fields
from evals.cve.nuisance.admission.walk import acceptance_target_servers, reached_servers
from evals.cve.nuisance.admission.walk_record import load_walk_record
from evals.cve.nuisance.commands import WALK_RECORD_PATH
from evals.cve.nuisance.fingerprint import nuisance_fixture_fingerprint
from evals.cve.nuisance.holdout_servers import run_population
from evals.honeypots import REPO_ROOT
from evals.run_census import CENSUS_PATH
from tests.unit.support.test_nuisance_committed_admission_given import (
    current_copy_fingerprints,
    the_committed_admission,
    the_committed_walk_inputs,
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


def test_every_recorded_exit_is_dated_by_an_entry_of_the_nuisance_suite_log():
    log = (REPO_ROOT / "docs" / "nuisance-suite-log.md").read_text()
    entry_dates = set(re.findall(r"^- (\d{4}-\d{2}-\d{2}):", log, flags=re.MULTILINE))

    undated = [
        recorded.server_package
        for recorded in the_committed_admission().exits
        if recorded.logged_on.isoformat() not in entry_dates
    ]

    assert undated == []


def test_every_reached_server_is_audited_out_or_pending_exactly_once():
    walk_inputs = the_committed_walk_inputs()
    reached = reached_servers(walk_inputs)
    population = run_population(
        reached, the_committed_admission(), acceptance_target_servers(walk_inputs)
    )
    accounted = Counter(
        [
            *(server.server_package for server in population.audited),
            *(row.server_package for row in population.exits),
            *population.pending,
        ]
    )

    reached_packages = [
        *(server.server_package for server in reached.listed),
        *reached.without_candidates,
    ]
    assert {package: accounted[package] for package in reached_packages} == dict.fromkeys(
        reached_packages, 1
    )
