from urllib.parse import urlsplit

import pytest

import tests.integration.committed.cve.backends.support.test_backend_hostnames_given as given
from evals.cve.backends.doris import DORIS_SERVER_LAUNCH
from evals.cve.backends.gravitino import GRAVITINO_PARTS, GRAVITINO_SERVER_LAUNCH
from evals.cve.nuisance.admission.admission import AdmittedServer
from tests.unit.support.docker_argv import value_after

_AUDIT_WORDS = ("mcp-auditor", "mcpaudit")


def test_the_doris_server_is_launched_at_the_clusters_alias():
    launch = given.the_admitted_server("doris").launch

    assert launch == DORIS_SERVER_LAUNCH


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
    launch = given.the_admitted_server("gravitino").launch

    uri = urlsplit(value_after(launch, "--gravitino-uri"))

    assert launch == GRAVITINO_SERVER_LAUNCH
    assert uri.hostname in {part.alias for part in GRAVITINO_PARTS}


def test_the_gravitino_catalogs_reach_postgresql_and_kafka_at_their_aliases():
    properties = given.gravitino_catalog_properties()

    assert {part.alias for part in GRAVITINO_PARTS} == {"gravitino", "postgresql", "kafka"}
    assert properties["catalog_postgres"]["jdbc-url"] == "jdbc:postgresql://postgresql/db"
    assert properties["catalog_kafka"]["bootstrap.servers"] == "kafka:9092"
    assert given.kafka_advertised_listeners() == "PLAINTEXT://kafka:9092"


def test_no_gravitino_alias_or_seeded_value_names_the_audit():
    values = [
        *(part.alias for part in GRAVITINO_PARTS),
        *given.gravitino_seeded_values(),
        *(value for part in GRAVITINO_PARTS for value in given.part_dockerfile_env(part).values()),
    ]

    naming = [value for value in values if any(word in value for word in _AUDIT_WORDS)]

    assert naming == []
