from evals.cve.backends.gravitino import GRAVITINO_PORT
from evals.cve.nuisance.fix_checks import cve_2026_41041_gravitino as gravitino
from evals.cve.planting_base import memory_bound_args
from tests.unit.support.docker_argv import carries


def test_the_server_points_at_the_per_launch_stack_not_the_run_singleton():
    network = "mcp-auditor-kit-gravitino-net-abcdef"
    args = gravitino.server_args("mcp-auditor-kit-gravitino:local", network)

    assert args[args.index("--network") + 1] == network
    assert args[args.index("--metalake") + 1] == "metalake_demo"
    assert args[args.index("--gravitino-uri") + 1] == f"http://gravitino:{GRAVITINO_PORT}"


def test_the_server_runs_under_the_confinement_of_the_cve_benchmark():
    args = gravitino.server_args("img", "net")

    assert "--cap-drop" in args and "ALL" in args
    assert carries(args, memory_bound_args())
    assert "--user" in args


def test_each_part_joins_the_per_launch_network_under_its_alias():
    args = gravitino.part_args("c", "net", "postgresql", "mcp-auditor-cve-gravitino-db:local")

    assert args[args.index("--network") + 1] == "net"
    assert args[args.index("--network-alias") + 1] == "postgresql"
    assert "--cap-drop" in args and "ALL" in args
    assert carries(args, memory_bound_args())
    assert args[-1] == "mcp-auditor-cve-gravitino-db:local"


def test_one_exploit_and_one_benign_call_per_counted_tool():
    assert len(gravitino.EXPLOITS) == len(gravitino.BENIGN_CALLS) == 27
