import itertools

from tests.fakes.planting_docker import FakePlantingDocker


def mounted_content(docker: FakePlantingDocker, run_args: list[str], container_path: str) -> str:
    mounts = [value for flag, value in itertools.pairwise(run_args) if flag == "-v"]
    host_path = next(
        mount.split(":")[0] for mount in mounts if mount.split(":")[1] == container_path
    )
    return docker.host_files[host_path].content


def nothing_left_alive(docker: FakePlantingDocker) -> None:
    assert docker.networks == set()
    assert docker.holders == {}
    assert docker.sentinels == {}
    assert docker.stand_ins == {}
    assert docker.host_files == {}


def added_hosts(run_args: list[str]) -> list[str]:
    return [value for flag, value in itertools.pairwise(run_args) if flag == "--add-host"]
