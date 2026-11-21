from tests.fakes.planting_docker import FakePlantingDocker


def nothing_left_alive(docker: FakePlantingDocker) -> None:
    assert docker.networks == set()
    assert docker.holders == {}
    assert docker.sentinels == {}
    assert docker.stand_ins == {}
    assert docker.host_files == {}
    assert docker.layouts == {}
