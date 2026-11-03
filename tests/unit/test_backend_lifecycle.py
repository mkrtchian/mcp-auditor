import pytest

import tests.unit.support.test_backend_lifecycle_given as given
from evals import doris_backend, mysql_backend, neo4j_backend
from evals.nuisance_backends import BACKENDS
from evals.nuisance_confinement import MEMORY_BOUND, memory_bound_args


def _carries(args: list[str], segment: list[str]) -> bool:
    return any(args[i : i + len(segment)] == segment for i in range(len(args)))


@pytest.mark.parametrize("key", sorted(BACKENDS))
def test_a_backend_module_lifecycle_carries_its_registry_key(key: str):
    assert given.a_lifecycle(key).key == key


@pytest.mark.parametrize("key", sorted(BACKENDS))
def test_every_backend_server_argv_carries_the_memory_bound(key: str):
    args = given.a_lifecycle(key).server_args("name", "image", given.a_host(), ["serve"])

    assert _carries(args, ["--memory", MEMORY_BOUND, "--memory-swap", MEMORY_BOUND])


def test_every_responder_singleton_argv_carries_the_memory_bound():
    responders = given.every_responder()

    assert len(responders) == 11
    for responder in responders:
        assert _carries(responder.singleton_run_args(), memory_bound_args()), responder.container


@pytest.mark.parametrize(
    "args",
    [
        doris_backend.doris_cluster_run_args(),
        mysql_backend.backend_container_run_args(
            mysql_backend.MYSQL_CONTAINER, [mysql_backend.MYSQL_IMAGE]
        ),
        mysql_backend.backend_container_run_args(mysql_backend.MOTO_CONTAINER, ["moto"]),
        neo4j_backend.database_run_args(),
    ],
    ids=["doris cluster", "mysql engine", "moto stub", "neo4j database"],
)
def test_every_built_backend_container_argv_carries_the_memory_bound(args: list[str]):
    assert _carries(args, memory_bound_args())
