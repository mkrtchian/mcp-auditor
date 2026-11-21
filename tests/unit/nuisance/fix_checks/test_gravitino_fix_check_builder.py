from evals.cve.backends.gravitino import GRAVITINO_PORT
from evals.cve.nuisance.fix_checks import cve_2026_41041_gravitino as gravitino
from tests.unit.support.docker_argv import value_after


def test_the_server_points_at_the_per_launch_stack_not_the_run_singleton():
    network = "mcp-auditor-kit-gravitino-net-abcdef"
    args = gravitino.server_args("mcp-auditor-kit-gravitino:local", network)

    assert value_after(args, "--network") == network
    assert value_after(args, "--metalake") == "metalake_demo"
    assert value_after(args, "--gravitino-uri") == f"http://gravitino:{GRAVITINO_PORT}"


def test_each_part_joins_the_per_launch_network_under_its_alias():
    args = gravitino.part_args("c", "net", "postgresql", "mcp-auditor-cve-gravitino-db:local")

    assert value_after(args, "--network") == "net"
    assert value_after(args, "--network-alias") == "postgresql"
    assert args[-1] == "mcp-auditor-cve-gravitino-db:local"
