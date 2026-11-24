from collections.abc import Sequence

from tests.fakes.planting_docker import FakePlantingDocker
from tests.unit.support.docker_argv import mount_of


def mounted_content(
    docker: FakePlantingDocker, run_args: Sequence[str], container_path: str
) -> str:
    host_path = mount_of(run_args, container_path).split(":")[0]
    return docker.host_files[host_path].content
