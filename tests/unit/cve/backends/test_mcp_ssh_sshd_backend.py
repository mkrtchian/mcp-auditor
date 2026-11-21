import base64

import tests.unit.cve.backends.support.test_mcp_ssh_sshd_backend_given as given
from evals.cve.backends.mcp_ssh_sshd import (
    SSH_CONFIG_HOST,
    SSHD_ALIAS,
    SSHD_PORT,
    singleton_run_args,
)
from tests.unit.support.docker_argv import carries, value_after


def test_the_mcp_ssh_config_is_the_readme_production_entry():
    config = given.mcp_ssh_config()

    assert config == {
        "Host": SSH_CONFIG_HOST,
        "Hostname": SSHD_ALIAS,
        "User": "deploy",
        "IdentityFile": "~/.ssh/id_production",
        "IdentitiesOnly": "yes",
    }


def test_the_sshd_answers_at_the_hostname_the_mcp_ssh_config_names_on_the_default_port():
    assert SSHD_PORT == 22
    assert carries(singleton_run_args(), ["--network-alias", SSHD_ALIAS])


def test_the_sshd_serves_the_account_the_mcp_ssh_config_names():
    assert given.sshd_account() == "deploy"


def test_the_mcp_ssh_benign_calls_name_the_config_host():
    aliases = given.benign_host_aliases()

    assert aliases and set(aliases) == {SSH_CONFIG_HOST}


def test_the_mcp_ssh_key_halves_are_one_pair_with_the_readme_comment():
    authorized = given.sshd_authorized_key_fields()
    private = given.mcp_ssh_private_key()

    assert len(authorized) == 3
    assert base64.b64decode(authorized[1]) == private.public_blob
    assert authorized[2] == private.comment == "production-server"


def test_the_sshd_singleton_runs_hardened_under_the_memory_bound():
    args = singleton_run_args()

    assert carries(args, ["--cap-drop", "ALL"])
    assert "--cap-add" not in args
    assert carries(args, ["--security-opt", "no-new-privileges"])
    assert 0 < int(value_after(args, "--pids-limit")) <= 256
    assert carries(args, ["--memory", "4g", "--memory-swap", "4g"])
