from typing import Any

import pytest
import yaml

from evals import nuisance_images
from evals.cve_images import COMPOSE_FILE
from evals.holdout_census import load_census
from evals.nuisance_admission import ADMISSION_PATH, AdmittedServer, load_admission
from evals.nuisance_commands import WALK_RECORD_PATH
from evals.nuisance_walk_record import load_walk_record
from evals.run_census import CENSUS_PATH

COMPOSE_SERVICES: dict[str, Any] = yaml.safe_load(COMPOSE_FILE.read_text())["services"]


def _admitted_servers() -> list[AdmittedServer]:
    if not ADMISSION_PATH.exists():
        return []
    census = load_census(CENSUS_PATH)
    return list(load_admission(ADMISSION_PATH, load_walk_record(WALK_RECORD_PATH, census)).servers)


ADMITTED = _admitted_servers()


@pytest.mark.parametrize("server", ADMITTED, ids=lambda server: server.service)
def test_each_admitted_server_is_a_nuisance_profiled_compose_service(server: AdmittedServer):
    compose_service = COMPOSE_SERVICES.get(server.service)

    assert compose_service is not None, f"{server.service}: no service in {COMPOSE_FILE}"
    assert compose_service["image"] == nuisance_images.image_tag(server.service)
    assert compose_service.get("profiles") == ["nuisance"]


@pytest.mark.parametrize("server", ADMITTED, ids=lambda server: server.service)
def test_each_admitted_server_has_a_fixture_fingerprint(server: AdmittedServer):
    nuisance_images.nuisance_fixture_fingerprint(server)
