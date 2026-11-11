import re

from evals.mcp_ssh_sshd_backend import SSHD_ALIAS, SSHD_IMAGE
from evals.nuisance_fix_checks import mcp_ssh_fix_check as fix_check


def test_the_sshd_joins_the_per_launch_network_under_the_run_host_alias():
    args = fix_check.sshd_args("mcp-auditor-kit-mcp-ssh-sshd-abcd", "net")

    assert args[args.index("--network") + 1] == "net"
    assert args[args.index("--network-alias") + 1] == SSHD_ALIAS == "sshhost"
    assert args[-1] == SSHD_IMAGE


def test_the_per_launch_sshd_runs_under_the_holdout_confinement_without_the_memory_bound():
    args = fix_check.sshd_args("c", "net")

    assert "--cap-drop" in args and "ALL" in args
    assert "--memory" not in args


def test_the_server_joins_the_per_launch_network_not_the_singleton_bridge():
    args = fix_check.server_args("img", "net", "/tmp/w")

    assert args[args.index("--network") + 1] == "net"
    assert "mcp-auditor-cve-mcp-ssh-sshd-bridge" not in args
    assert "--memory" not in args
    assert "--user" in args


def test_the_server_mounts_the_witness_read_only():
    args = fix_check.server_args("img", "net", "/tmp/witness-file")

    assert "-v" in args
    assert f"/tmp/witness-file:{fix_check.WITNESS_PATH}:ro" in args


def test_the_shell_injection_runs_the_cat_locally_and_the_option_one_supplies_proxycommand():
    assert fix_check.shell_injection("/tmp/secret").startswith('nohost";')
    assert "cat /tmp/secret" in fix_check.shell_injection("/tmp/secret")
    assert fix_check.option_injection("/tmp/secret").startswith("-oProxyCommand=")


def test_five_exploits_and_three_benign_calls():
    built = fix_check.target(
        flaw="CVE-2025-9654",
        aim=re.compile(r'";'),
        injection=fix_check.shell_injection,
        vulnerable_service="mcp-ssh-flaw-1.0.3",
        patched_service="mcp-ssh-flaw-1.0.4",
        server_patched_service="mcp-ssh",
    )

    assert len(built.exploits) == 5
    assert len(built.benign_calls) == 3
