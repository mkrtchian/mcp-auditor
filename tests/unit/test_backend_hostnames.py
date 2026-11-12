import base64

import pytest

import tests.unit.support.test_backend_hostnames_given as given
from evals.cve.backends.doris import DORIS_HOST, DORIS_SERVER_LAUNCH
from evals.cve.backends.gravitino import GRAVITINO_PARTS, GRAVITINO_SERVER_LAUNCH
from evals.cve.backends.mcp_ssh_sshd import SSHD_ALIAS, SSHD_PORT, singleton_run_args
from evals.cve.nuisance.admission import AdmittedServer
from tests.unit.support.docker_argv import carries

_AUDIT_WORDS = ("mcp-auditor", "mcpaudit")


def test_the_doris_server_is_launched_at_the_clusters_alias():
    launch = given.the_admitted_server("doris").launch

    assert launch == DORIS_SERVER_LAUNCH
    assert DORIS_SERVER_LAUNCH == ["--db-host", DORIS_HOST]


def test_the_mysql_benign_call_reaches_the_engine_in_its_own_image():
    assert given.the_benign_argument("mysql", "db_endpoint") == "127.0.0.1"


@pytest.mark.parametrize("server", given.admitted_servers(), ids=lambda server: server.service)
def test_no_value_reaching_an_admitted_server_names_the_audit(server: AdmittedServer):
    values = [
        *server.launch,
        *given.benign_argument_values(server),
        *given.run_dockerfile_env(server).values(),
    ]

    naming = [value for value in values if any(word in value for word in _AUDIT_WORDS)]

    assert naming == []


def test_the_gravitino_server_is_launched_at_the_instances_alias():
    assert GRAVITINO_SERVER_LAUNCH == [
        "--metalake", "analytics", "--gravitino-uri", "http://gravitino:8090",
    ]  # fmt: skip


def test_the_gravitino_catalogs_reach_postgres_and_kafka_at_their_aliases():
    properties = given.gravitino_catalog_properties()

    assert {part.alias for part in GRAVITINO_PARTS} == {"gravitino", "postgres", "kafka"}
    assert properties["warehouse"]["jdbc-url"] == "jdbc:postgresql://postgres:5432/warehouse"
    assert properties["streams"]["bootstrap.servers"] == "kafka:9092"
    assert given.kafka_advertised_listeners() == "PLAINTEXT://kafka:9092"


def test_no_gravitino_alias_or_seeded_value_names_the_audit():
    values = [
        *(part.alias for part in GRAVITINO_PARTS),
        *given.gravitino_seeded_values(),
        *(value for part in GRAVITINO_PARTS for value in given.part_dockerfile_env(part).values()),
    ]

    naming = [value for value in values if any(word in value for word in _AUDIT_WORDS)]

    assert naming == []


def test_the_sshd_answers_at_the_host_the_mcp_ssh_config_names():
    config = given.mcp_ssh_config()

    assert config["HostName"] == SSHD_ALIAS == "sshhost"
    assert config["Port"] == str(SSHD_PORT)
    assert carries(singleton_run_args(), ["--network-alias", SSHD_ALIAS])


def test_the_mcp_ssh_key_halves_are_one_pair_with_no_comment():
    authorized = given.sshd_authorized_key_fields()
    private = given.mcp_ssh_private_key()

    assert len(authorized) == 2
    assert base64.b64decode(authorized[1]) == private.public_blob
    assert private.comment == ""
