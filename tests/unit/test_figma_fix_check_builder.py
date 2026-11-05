from evals.cve_planting import PlantedArgs
from evals.figma_backend import FIGMA_BRIDGE
from evals.nuisance_fix_checks.cve_2025_15061_figma import server_args
from tests.unit.support.docker_argv import mount_of, value_after


def test_the_server_keeps_the_planted_user_and_mount_but_joins_the_figma_bridge():
    planted = PlantedArgs(
        user=("--user", "65534:65534"),
        working_directory=("-w", "/"),
        env=(),
        mounts=("-v", "/tmp/w:/witness:ro"),
        hostname=(),
        network=("--network", "none"),
    )

    args = server_args("figma:local", planted)

    assert mount_of(args, "/witness") == "/tmp/w:/witness:ro"
    assert value_after(args, "--user") == "65534:65534"
    assert value_after(args, "--network") == FIGMA_BRIDGE
    assert "none" not in args
    assert args[-2:] == ["figma:local", "--stdio"]
