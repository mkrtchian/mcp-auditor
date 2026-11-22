import base64

import tests.integration.committed.cve.backends.support.test_mcp_ssh_sshd_backend_given as given
from evals.cve.backends.mcp_ssh_sshd import SSH_CONFIG_HOST, SSHD_ALIAS


def test_the_mcp_ssh_config_is_the_readme_production_entry():
    config = given.mcp_ssh_config()

    assert config == {
        "Host": SSH_CONFIG_HOST,
        "Hostname": SSHD_ALIAS,
        "User": "deploy",
        "IdentityFile": "~/.ssh/id_production",
        "IdentitiesOnly": "yes",
    }


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
