import pytest

from evals.cve import images as cve_images
from evals.cve.backends.responder import Responder
from evals.cve.nuisance.backend_registry import BACKENDS
from evals.cve.nuisance.fixtures import FIX_CHECK_FIXTURES
from tests.unit.support.registered_responders import every_responder


@pytest.mark.parametrize("key", sorted(BACKENDS))
def test_a_backend_built_locally_names_the_compose_service_of_its_image(key: str):
    entry = BACKENDS[key]
    tags = [cve_images.image_tag(service) for service in entry.built_services]

    for image in entry.images:
        assert image in tags if _is_built(image) else "@sha256:" in image
    if not any(_is_built(image) for image in entry.images):
        assert tags == []


def _is_built(image: str) -> bool:
    return image.startswith("mcp-auditor-cve-") and image.endswith(":local")


_BACKEND_ON = {entry.network: entry for entry in BACKENDS.values()}


@pytest.mark.parametrize(
    "responder",
    [responder for responder in every_responder() if responder.bridge in _BACKEND_ON],
    ids=lambda r: r.container,
)
def test_every_run_responder_image_is_rebuilt_with_its_backend(responder: Responder):
    built = _BACKEND_ON[responder.bridge].built_services

    assert responder.image in [cve_images.image_tag(service) for service in built]


@pytest.mark.parametrize(
    "responder",
    [responder for responder in every_responder() if responder.bridge not in _BACKEND_ON],
    ids=lambda r: r.container,
)
def test_every_fix_check_responder_image_is_rebuilt_by_a_fix_check_naming_it(
    responder: Responder,
):
    named = (
        service for fixture in FIX_CHECK_FIXTURES for service in fixture.backend_services or ()
    )

    assert responder.image in [cve_images.image_tag(service) for service in named]
