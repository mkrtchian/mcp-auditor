from collections.abc import Sequence

from evals.cve_planting_base import resolver_args
from tests.fakes.planting_docker import FakePlantingDocker


def nothing_left_alive(docker: FakePlantingDocker) -> None:
    assert docker.networks == set()
    assert docker.holders == {}
    assert docker.sentinels == {}
    assert docker.stand_ins == {}
    assert docker.host_files == {}
    assert docker.layouts == {}


def resolver_options_in(argv: Sequence[str]) -> int:
    option = resolver_args()
    width = len(option)
    return sum(list(argv[i : i + width]) == option for i in range(len(argv) - width + 1))
