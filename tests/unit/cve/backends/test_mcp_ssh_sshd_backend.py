from evals.cve.backends.mcp_ssh_sshd import SSHD_ALIAS, SSHD_PORT, singleton_run_args
from tests.unit.support.docker_argv import carries


def test_the_sshd_answers_at_the_hostname_the_mcp_ssh_config_names_on_the_default_port():
    assert SSHD_PORT == 22
    assert carries(singleton_run_args(), ["--network-alias", SSHD_ALIAS])
