import dataclasses
from collections.abc import Generator
from contextlib import contextmanager
from pathlib import Path

import tests.unit.cve.support.test_cve_planting_stand_ins_given as stand_ins_given
from evals.cve.nuisance.confinement import single_container_launch_args
from evals.cve.planting_base import PlantingHost, PublicNames, SymbolicUser

HOST = PlantingHost(SymbolicUser.UNPRIVILEGED, "/srv", has_network=False)
LAUNCH = ["node", "dist/index.js"]
IMAGE = "image:local"


@dataclasses.dataclass(frozen=True)
class ServedLaunch:
    args: list[str]
    docker: stand_ins_given.FakePlantingDocker


@contextmanager
def a_launch_serving(
    tmp_path: Path, names: PublicNames, working_directory: str = HOST.working_directory
) -> Generator[ServedLaunch]:
    """The single-container launch of `HOST` in `working_directory`, serving `names` from a
    stand-ins directory, its argv and the fake Docker that planted it."""
    docker = stand_ins_given.FakePlantingDocker()
    host = dataclasses.replace(HOST, working_directory=working_directory, public_names=names)
    with single_container_launch_args(
        IMAGE,
        host,
        LAUNCH,
        docker=docker,
        stand_ins_directory=stand_ins_given.a_stand_ins_directory(tmp_path),
    ) as args:
        yield ServedLaunch(args, docker)
