from evals.nuisance_fix_checks import cve_2026_35402_neo4j_cypher as neo4j_cypher
from tests.unit.support.docker_argv import environment, value_after


def test_the_server_logs_in_with_the_databases_password_at_its_alias():
    database = neo4j_cypher.neo4j_container_args("name")
    server = environment(neo4j_cypher.server_args("image"))

    password = environment(database)["NEO4J_AUTH"].split("/", 1)[1]
    assert server["NEO4J_PASSWORD"] == password
    assert server["NEO4J_URI"].split("//")[1].split(":")[0] == value_after(
        database, "--network-alias"
    )


def test_the_sentinel_serves_the_witness_coordinates():
    args = neo4j_cypher.sentinel_args("name", "nonce-value")

    assert value_after(args, "--network-alias") == neo4j_cypher.WITNESS.coordinates.host
    assert f"SERVE_FILE={neo4j_cypher.WITNESS.coordinates.path}" in args


def test_only_the_server_is_confined_and_it_runs_read_only():
    database = neo4j_cypher.neo4j_container_args("name")
    server = neo4j_cypher.server_args("image")

    assert "--cap-drop" not in database
    assert "--security-opt" not in database
    assert "--cap-drop" in server
    assert value_after(server, "--user") == "65534:65534"
    assert server[-2:] == ["image", "--read-only"]
