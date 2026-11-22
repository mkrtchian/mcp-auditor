from typing import Any

import pytest
import yaml

from evals.cve.detection.holdout_targets import HOLDOUT_TARGETS
from evals.cve.detection.targets import ACCEPTANCE_TARGETS, image_tag
from evals.cve.images import COMPOSE_FILE
from evals.cve.nuisance import images as nuisance_images
from evals.cve.nuisance.admission.admission import AdmittedServer
from evals.cve.nuisance.backend_registry import BACKENDS
from tests.unit.support.test_nuisance_committed_admission_given import the_committed_admission

COMPOSE_SERVICES: dict[str, Any] = yaml.safe_load(COMPOSE_FILE.read_text())["services"]


ADMITTED = list(the_committed_admission().servers)


@pytest.mark.parametrize("server", ADMITTED, ids=lambda server: server.service)
def test_each_admitted_server_is_a_nuisance_profiled_compose_service(server: AdmittedServer):
    compose_service = COMPOSE_SERVICES.get(server.service)

    assert compose_service is not None, f"{server.service}: no service in {COMPOSE_FILE}"
    assert compose_service["image"] == nuisance_images.image_tag(server.service)
    assert compose_service.get("profiles") == ["nuisance"]


BUILT_SERVICES = {service for entry in BACKENDS.values() for service in entry.built_services}
# The CI's bare build, which skips the nuisance profile, builds what detection targets run.
DETECTION_SERVICES = {
    image for target in (*ACCEPTANCE_TARGETS, *HOLDOUT_TARGETS) for image in target.images
} & BUILT_SERVICES


@pytest.mark.parametrize("service", sorted(BUILT_SERVICES))
def test_each_built_backend_is_a_compose_service_profiled_nuisance_but_the_detection_ones(
    service: str,
):
    compose_service = COMPOSE_SERVICES.get(service)
    profiles = None if service in DETECTION_SERVICES else ["nuisance"]

    assert compose_service is not None, f"{service}: no service in {COMPOSE_FILE}"
    assert compose_service["image"] == image_tag(service)
    assert compose_service.get("profiles") == profiles
