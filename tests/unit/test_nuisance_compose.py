from typing import Any

import pytest
import yaml

from evals import nuisance_images
from evals.cve_images import COMPOSE_FILE
from evals.cve_planting_base import STAND_IN_SERVICE
from evals.cve_targets import image_tag
from evals.nuisance_admission import AdmittedServer
from evals.nuisance_backends import BACKENDS
from evals.nuisance_fingerprint import nuisance_fixture_fingerprint
from tests.unit.support.test_nuisance_committed_admission_given import the_committed_admission

COMPOSE_SERVICES: dict[str, Any] = yaml.safe_load(COMPOSE_FILE.read_text())["services"]


ADMITTED = list(the_committed_admission().servers)


@pytest.mark.parametrize("server", ADMITTED, ids=lambda server: server.service)
def test_each_admitted_server_is_a_nuisance_profiled_compose_service(server: AdmittedServer):
    compose_service = COMPOSE_SERVICES.get(server.service)

    assert compose_service is not None, f"{server.service}: no service in {COMPOSE_FILE}"
    assert compose_service["image"] == nuisance_images.image_tag(server.service)
    assert compose_service.get("profiles") == ["nuisance"]


BUILT_SERVICES = sorted(
    {service for entry in BACKENDS.values() for service in entry.built_services}
)


@pytest.mark.parametrize("service", BUILT_SERVICES)
def test_each_built_backend_is_a_compose_service_profiled_nuisance_but_the_stand_in(service: str):
    compose_service = COMPOSE_SERVICES.get(service)
    # The CI's bare build, which skips the nuisance profile, builds the stand-in.
    profiles = None if service == STAND_IN_SERVICE else ["nuisance"]

    assert compose_service is not None, f"{service}: no service in {COMPOSE_FILE}"
    assert compose_service["image"] == image_tag(service)
    assert compose_service.get("profiles") == profiles


@pytest.mark.parametrize("server", ADMITTED, ids=lambda server: server.service)
def test_each_admitted_server_has_a_fixture_fingerprint(server: AdmittedServer):
    nuisance_fixture_fingerprint(server)
