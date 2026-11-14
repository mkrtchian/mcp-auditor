import tempfile
from collections.abc import Generator
from contextlib import AbstractContextManager, contextmanager
from pathlib import Path
from typing import Any, Protocol

from evals.cve.places import Coordinates, Place, PlaceKind
from evals.cve.planting import (
    RANDOM_NONCES,
    PlantingHost,
    PlantingSpec,
    SymbolicUser,
    planting_spec,
)
from evals.cve.planting_base import LAYOUT_PREFIX, LayoutMount
from tests.fakes.planting_docker import FakePlantingDocker


class Builder(Protocol):
    def __call__(
        self, image: str, spec: PlantingSpec, *, docker: FakePlantingDocker
    ) -> AbstractContextManager[Any]: ...


def an_empty_spec(mount: LayoutMount = LayoutMount.READ_ONLY) -> PlantingSpec:
    host = PlantingHost(SymbolicUser.UNPRIVILEGED, "/", has_network=False, layout_mount=mount)
    return planting_spec((), host, RANDOM_NONCES)


def a_spec_with_a_file_place() -> PlantingSpec:
    place = Place(
        id="file-1",
        family="fictional",
        reaches=frozenset({"arbitrary_read"}),
        kind=PlaceKind.FILE,
        coordinates=Coordinates(PlaceKind.FILE, path="/etc/fictional/secret"),
    )
    return planting_spec((place,), _no_network_host(), RANDOM_NONCES)


def _no_network_host() -> PlantingHost:
    return PlantingHost(SymbolicUser.UNPRIVILEGED, "/", has_network=False)


@contextmanager
def paths_the_removal_refuses(tmp_path: Path) -> Generator[list[str]]:
    """A prefixed directory outside the system temp directory, an unprefixed child of it, a path
    nested under a prefixed child of it and the empty string, each an existing directory but the
    last."""
    elsewhere = tmp_path / f"{LAYOUT_PREFIX}elsewhere"
    elsewhere.mkdir()
    with (
        tempfile.TemporaryDirectory(prefix="unprefixed-") as unprefixed,
        tempfile.TemporaryDirectory(prefix=LAYOUT_PREFIX) as outer,
    ):
        nested = Path(outer) / "srv"
        nested.mkdir()
        yield [str(elsewhere), unprefixed, str(nested), ""]
