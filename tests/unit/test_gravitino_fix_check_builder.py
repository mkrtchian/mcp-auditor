from evals.cve.backends.gravitino import GRAVITINO_PORT
from evals.cve.nuisance.fix_checks import cve_2026_41041_gravitino as gravitino


def test_the_server_points_at_the_per_launch_stack_not_the_run_singleton():
    network = "mcp-auditor-kit-gravitino-net-abcdef"
    args = gravitino.server_args("mcp-auditor-kit-gravitino:local", network)

    assert args[args.index("--network") + 1] == network
    assert args[args.index("--metalake") + 1] == "analytics"
    assert args[args.index("--gravitino-uri") + 1] == f"http://gravitino:{GRAVITINO_PORT}"


def test_the_server_runs_under_the_holdout_confinement_without_the_memory_bound():
    args = gravitino.server_args("img", "net")

    assert "--cap-drop" in args and "ALL" in args
    assert "--memory" not in args
    assert "--user" in args


def test_each_part_joins_the_per_launch_network_under_its_alias_without_the_memory_bound():
    args = gravitino.part_args("c", "net", "postgres", "mcp-auditor-cve-gravitino-db:local")

    assert args[args.index("--network") + 1] == "net"
    assert args[args.index("--network-alias") + 1] == "postgres"
    assert "--cap-drop" in args and "ALL" in args
    assert "--memory" not in args
    assert args[-1] == "mcp-auditor-cve-gravitino-db:local"


def test_one_exploit_and_one_benign_call_per_counted_tool():
    assert len(gravitino.EXPLOITS) == len(gravitino.BENIGN_CALLS) == 27
