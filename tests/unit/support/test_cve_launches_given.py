import tempfile
from collections.abc import Generator
from contextlib import contextmanager
from pathlib import Path

from evals.cve_places import Coordinates, Place, PlantKind
from evals.cve_planting import (
    RANDOM_NONCES,
    PlantingHost,
    PlantingSpec,
    SymbolicUser,
    planting_spec,
)
from evals.cve_planting_base import LAYOUT_PREFIX


def an_empty_spec() -> PlantingSpec:
    return planting_spec((), _no_network_host(), RANDOM_NONCES)


def a_spec_with_a_file_place() -> PlantingSpec:
    place = Place(
        id="file-1",
        family="fictional",
        reachable_by=frozenset({"arbitrary_read"}),
        kind=PlantKind.FILE,
        coordinates=Coordinates(PlantKind.FILE, path="/etc/fictional/secret"),
    )
    return planting_spec((place,), _no_network_host(), RANDOM_NONCES)


def _no_network_host() -> PlantingHost:
    return PlantingHost(SymbolicUser.UNPRIVILEGED, "/", has_network=False)


@contextmanager
def paths_the_removal_refuses(tmp_path: Path, root: Path) -> Generator[list[str]]:
    """A prefixed directory outside the system temp directory, an unprefixed child of it, a path
    nested under a prefixed directory and the empty string, each an existing directory but the
    last."""
    elsewhere = tmp_path / f"{LAYOUT_PREFIX}elsewhere"
    elsewhere.mkdir()
    with tempfile.TemporaryDirectory(prefix="unprefixed-") as unprefixed:
        yield [str(elsewhere), unprefixed, str(root), ""]
