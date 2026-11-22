from pathlib import Path

from evals.cve.planting import PlantingSpec
from evals.cve.planting_base import PublicNames
from tests.unit.support.fictional_planting import (
    endpoint_place,
    file_place,
    spec_of,
    unprivileged_host,
)
from tests.unit.support.fictional_stand_ins import HOST


def capture_text(directory: Path) -> str:
    return (directory / f"{HOST}.json").read_text()


def a_spec_with_the_stand_in(
    *, trust: tuple[str, ...] = (), endpoint_host: str | None = None
) -> PlantingSpec:
    places = [endpoint_place(host=endpoint_host)] if endpoint_host is not None else []
    names = PublicNames(stand_ins=(HOST,), trust=trust)
    return spec_of(places, host=unprivileged_host(has_network=True, public_names=names))


def a_spec_without_public_names() -> PlantingSpec:
    return spec_of([file_place()], host=unprivileged_host(has_network=True))
