from tests.fakes.planting_docker import FakePlantingDocker
from tests.unit.support.docker_argv import mount_of, values_after


def mounted_content(docker: FakePlantingDocker, run_args: list[str], container_path: str) -> str:
    host_path = mount_of(run_args, container_path).split(":")[0]
    return docker.host_files[host_path].content


def nothing_left_alive(docker: FakePlantingDocker) -> None:
    assert docker.networks == set()
    assert docker.holders == {}
    assert docker.sentinels == {}
    assert docker.stand_ins == {}
    assert docker.host_files == {}


def added_hosts(run_args: list[str]) -> list[str]:
    return values_after(run_args, "--add-host")
