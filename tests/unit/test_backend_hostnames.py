import pytest

import tests.unit.support.test_backend_hostnames_given as given
from evals.doris_backend import DORIS_HOST, DORIS_SERVER_LAUNCH
from evals.nuisance_admission import AdmittedServer

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
