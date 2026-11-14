import tests.unit.nuisance.fix_checks.support.test_mcp_ssh_fix_check_builder_given as given
from evals.cve.backends.mcp_ssh_sshd import SSHD_ALIAS, SSHD_IMAGE, sshd_args
from evals.cve.nuisance.fix_checks import mcp_ssh_fix_check as fix_check
from tests.fakes import FakeKitClient
from tests.unit.support.docker_argv import carries, value_after


def test_the_per_launch_sshd_joins_its_network_under_the_run_host_alias():
    args = sshd_args("mcp-auditor-cve-mcp-ssh-sshd-abcd", "net")

    assert args[args.index("--network") + 1] == "net"
    assert args[args.index("--network-alias") + 1] == SSHD_ALIAS == "prod.example.com"
    assert args[-1] == SSHD_IMAGE


def test_the_per_launch_sshd_runs_hardened_without_the_memory_bound():
    args = sshd_args("c", "net")

    assert carries(args, ["--cap-drop", "ALL"])
    assert "--cap-add" not in args
    assert carries(args, ["--security-opt", "no-new-privileges"])
    assert 0 < int(value_after(args, "--pids-limit")) <= 256
    assert "--memory" not in args


def test_the_server_joins_the_per_launch_network_not_the_singleton_bridge():
    args = fix_check.server_args("img", given.an_sshd_on("net"), "/tmp/w")

    assert args[args.index("--network") + 1] == "net"
    assert "mcp-auditor-cve-mcp-ssh-sshd-bridge" not in args
    assert "--memory" not in args
    assert "--user" in args


def test_the_server_mounts_the_witness_read_only():
    args = fix_check.server_args("img", given.an_sshd_on("net"), "/tmp/witness-file")

    assert "-v" in args
    assert f"/tmp/witness-file:{fix_check.WITNESS_PATH}:ro" in args


def test_the_shell_injection_runs_the_cat_locally_and_the_option_one_supplies_proxycommand():
    assert fix_check.shell_injection("/tmp/secret").startswith('nohost";')
    assert "cat /tmp/secret" in fix_check.shell_injection("/tmp/secret")
    assert fix_check.option_injection("/tmp/secret").startswith("-oProxyCommand=")


def test_five_exploits_and_three_benign_calls():
    built = given.the_cve_2025_9654_fixture()

    assert len(built.exploits) == 5
    assert len(built.benign_calls) == 3


async def test_the_benign_calls_name_the_readme_production_host():
    client = FakeKitClient()
    for call in given.the_cve_2025_9654_fixture().benign_calls:
        await call({}, client)

    assert {args["hostAlias"] for _, args in client.calls} == {"production"}
