import tempfile
from collections.abc import Generator
from contextlib import contextmanager
from pathlib import Path

from evals.cve.planting import RANDOM_NONCES, PlantingSpec
from evals.cve.planting_base import LAYOUT_PREFIX
from tests.unit.support.fictional_planting import file_place, spec_of, unprivileged_host


def a_spec_with_a_file_place() -> PlantingSpec:
    return spec_of([file_place()], unprivileged_host(working_directory="/"), RANDOM_NONCES)


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
