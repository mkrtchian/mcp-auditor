import pytest

import tests.unit.support.test_nuisance_admission_given as given
from evals import nuisance_provisioners
from evals.neo4j_backend import NEO4J_BRIDGE, NEO4J_IMAGE
from evals.nuisance_admission import AdmittedServer, BackendFixture
from evals.nuisance_backends import BACKENDS, backend_problems
from evals.nuisance_images import image_tag
from evals.nuisance_provisioners import neo4j_provisioner


def _value_after(args: list[str], flag: str) -> str:
    return args[args.index(flag) + 1]


def _a_server() -> AdmittedServer:
    return given.an_admission().servers[0]


def test_the_neo4j_fixture_is_accepted_by_the_registry():
    backend = BackendFixture(provisioner="neo4j", image=NEO4J_IMAGE, network=NEO4J_BRIDGE)

    assert backend_problems(given.with_a_backend(_a_server(), backend), BACKENDS) == []


def test_neo4j_provisioner_wires_the_database_and_reaps_the_server(
    monkeypatch: pytest.MonkeyPatch,
):
    ensured: list[None] = []
    removed: list[str] = []

    def record_ensure() -> None:
        ensured.append(None)

    def record_rm(name: str) -> None:
        removed.append(name)

    monkeypatch.setattr(nuisance_provisioners, "ensure_neo4j", record_ensure)
    monkeypatch.setattr(nuisance_provisioners, "neo4j_rm", record_rm)
    server = _a_server()

    with neo4j_provisioner(server) as launch:
        assert _value_after(launch.args, "--network") == NEO4J_BRIDGE
        assert _value_after(launch.args, "--user") == "65534:65534"
        assert _value_after(launch.args, "-w") == "/"
        tail = [image_tag(server.service), *server.launch]
        assert launch.args[-len(tail) :] == tail
        assert len(ensured) == 1
        assert removed == []
        name = _value_after(launch.args, "--name")

    assert removed == [name]


def test_two_neo4j_provisioners_of_one_server_are_open_at_once(monkeypatch: pytest.MonkeyPatch):
    def noop_ensure() -> None:
        pass

    def noop_rm(name: str) -> None:
        pass

    monkeypatch.setattr(nuisance_provisioners, "ensure_neo4j", noop_ensure)
    monkeypatch.setattr(nuisance_provisioners, "neo4j_rm", noop_rm)
    server = _a_server()

    with neo4j_provisioner(server), neo4j_provisioner(server):
        pass
