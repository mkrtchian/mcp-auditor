from pathlib import Path

import tests.unit.support.fake_sshd as fake_sshd
from evals.cve.backends.mcp_ssh_sshd import CALLER, KNOWN_HOSTS, SSH_CONFIG_HOST, StoodSshd
from evals.cve.nuisance.fix_checks import mcp_ssh_fix_check as fix_check
from evals.cve.nuisance.fix_checks.cve_2025_9654_mcp_ssh import FIXTURES
from tests.fakes import FakeKitClient
from tests.unit.support.docker_argv import mount_of, value_after


def test_the_server_joins_the_per_launch_network_not_the_singleton_bridge():
    args = fix_check.server_args("img", StoodSshd("net", Path("/k/known_hosts")), "/tmp/w")

    assert value_after(args, "--network") == "net"
    assert "mcp-auditor-cve-mcp-ssh-sshd-bridge" not in args


def test_the_fix_check_stands_its_sshd_with_a_known_hosts_the_caller_owns(tmp_path: Path):
    sshd = fake_sshd.an_sshd(tmp_path)

    with fix_check.ssh_env("img", FIXTURES[0].planting_spec(), stand=sshd.stand) as launch:
        assert sshd.owners == [CALLER]
        assert mount_of(launch.args, KNOWN_HOSTS) == f"{sshd.known_hosts}:{KNOWN_HOSTS}:ro"
        assert value_after(launch.args, "--network") == "sshd-net-1"


def test_the_fix_check_server_mounts_the_known_hosts_beside_the_witness():
    args = fix_check.server_args("img", StoodSshd("net", Path("/k/known_hosts")), "/tmp/w")

    assert mount_of(args, KNOWN_HOSTS) == f"/k/known_hosts:{KNOWN_HOSTS}:ro"
    assert mount_of(args, fix_check.WITNESS_PATH) == f"/tmp/w:{fix_check.WITNESS_PATH}:ro"


def test_the_shell_injection_runs_the_cat_locally_and_the_option_one_supplies_proxycommand():
    assert fix_check.shell_injection("/tmp/secret").startswith('nohost";')
    assert "cat /tmp/secret" in fix_check.shell_injection("/tmp/secret")
    assert fix_check.option_injection("/tmp/secret").startswith("-oProxyCommand=")


async def test_the_fix_check_benign_calls_name_the_config_host():
    client = FakeKitClient()
    for call in FIXTURES[0].benign_calls:
        await call({}, client)

    assert {args["hostAlias"] for _, args in client.calls} == {SSH_CONFIG_HOST}
