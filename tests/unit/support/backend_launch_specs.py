"""Planting specs a backed launch builder takes: with a holder, without one, with no network, or
on a target's kept places."""

from evals.cve.detection.targets import Target
from evals.cve.places import DETECTION_PLACES, kept_records, load_places
from evals.cve.planting import RANDOM_NONCES, PlantingSpec, planting_spec
from evals.cve.planting_base import PlantingHost, SymbolicUser
from tests.unit.support.fictional_planting import endpoint_place


def a_spec_with_a_holder() -> PlantingSpec:
    # A link-local endpoint is bound inside a namespace holder the server joins.
    place = endpoint_place(host="169.254.169.254", path="/latest/meta-data/")
    spec = planting_spec((place,), _a_host(has_network=True), RANDOM_NONCES)
    assert spec.needs_holder
    return spec


def a_spec_without_a_holder() -> PlantingSpec:
    spec = planting_spec((), _a_host(has_network=True), RANDOM_NONCES)
    assert not spec.needs_holder
    return spec


def a_spec_with_no_network() -> PlantingSpec:
    return planting_spec((), _a_host(has_network=False), RANDOM_NONCES)


def a_spec_of_the_kept_places(target: Target) -> PlantingSpec:
    return target.planting_spec(kept_records(target.kept_places, load_places(DETECTION_PLACES)))


def _a_host(*, has_network: bool) -> PlantingHost:
    return PlantingHost(SymbolicUser.UNPRIVILEGED, "/", has_network=has_network)
