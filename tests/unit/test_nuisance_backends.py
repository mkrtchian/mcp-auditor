import pytest

import tests.unit.support.test_nuisance_admission_given as given
from evals import nuisance_backends
from evals.ckan_backend import CKAN_ALIASES, CKAN_BRIDGE, CKAN_RESPONDER_IMAGE, CKAN_RESPONDER_IP
from evals.contextforge_backend import CONTEXTFORGE_BRIDGE, CONTEXTFORGE_RESPONDER_IMAGE
from evals.doris_backend import DORIS_BRIDGE, DORIS_IMAGE
from evals.mysql_backend import MYSQL_BRIDGE, MYSQL_IMAGE
from evals.nuisance_admission import AdmittedServer, BackendFixture
from evals.nuisance_backends import (
    BACKENDS,
    backend_problems,
    ckan_provisioner,
    contextforge_provisioner,
    doris_provisioner,
    mysql_provisioner,
)
from evals.nuisance_images import image_tag


def _value_after(args: list[str], flag: str) -> str:
    return args[args.index(flag) + 1]


def _a_server() -> AdmittedServer:
    return given.an_admission().servers[0]


def test_the_doris_fixture_is_accepted_by_the_registry():
    backend = BackendFixture(provisioner="doris", image=DORIS_IMAGE, network=DORIS_BRIDGE)

    assert backend_problems(given.with_a_backend(_a_server(), backend), BACKENDS) == []


def test_doris_provisioner_wires_the_cluster_and_reaps_the_server(monkeypatch: pytest.MonkeyPatch):
    ensured: list[None] = []
    removed: list[str] = []

    def record_ensure() -> None:
        ensured.append(None)

    def record_rm(name: str) -> None:
        removed.append(name)

    monkeypatch.setattr(nuisance_backends, "ensure_doris", record_ensure)
    monkeypatch.setattr(nuisance_backends, "doris_rm", record_rm)
    server = _a_server()

    with doris_provisioner(server) as launch:
        assert _value_after(launch.args, "--network") == DORIS_BRIDGE
        assert _value_after(launch.args, "--user") == "65534:65534"
        assert _value_after(launch.args, "-w") == "/"
        tail = [image_tag(server.service), *server.launch]
        assert launch.args[-len(tail) :] == tail
        assert len(ensured) == 1
        assert removed == []
        name = _value_after(launch.args, "--name")

    assert removed == [name]


def test_two_doris_provisioners_of_one_server_are_open_at_once(monkeypatch: pytest.MonkeyPatch):
    def noop_ensure() -> None:
        pass

    def noop_rm(name: str) -> None:
        pass

    monkeypatch.setattr(nuisance_backends, "ensure_doris", noop_ensure)
    monkeypatch.setattr(nuisance_backends, "doris_rm", noop_rm)
    server = _a_server()

    with doris_provisioner(server), doris_provisioner(server):
        pass


def _values_after(args: list[str], flag: str) -> list[str]:
    return [args[index + 1] for index, arg in enumerate(args) if arg == flag]


def test_the_ckan_fixture_is_accepted_by_the_registry():
    backend = BackendFixture(provisioner="ckan", image=CKAN_RESPONDER_IMAGE, network=CKAN_BRIDGE)

    assert backend_problems(given.with_a_backend(_a_server(), backend), BACKENDS) == []


def test_ckan_provisioner_wires_the_responder_and_reaps_the_server(
    monkeypatch: pytest.MonkeyPatch,
):
    ensured: list[None] = []
    removed: list[str] = []

    def record_ensure() -> None:
        ensured.append(None)

    def record_rm(name: str) -> None:
        removed.append(name)

    monkeypatch.setattr(nuisance_backends, "ensure_ckan_responder", record_ensure)
    monkeypatch.setattr(nuisance_backends, "ckan_rm", record_rm)
    server = _a_server()

    with ckan_provisioner(server) as launch:
        assert _value_after(launch.args, "--network") == CKAN_BRIDGE
        assert _value_after(launch.args, "--user") == "65534:65534"
        assert _value_after(launch.args, "-w") == "/"
        assert _value_after(launch.args, "-e") == "NODE_TLS_REJECT_UNAUTHORIZED=0"
        aliases = _values_after(launch.args, "--add-host")
        assert aliases == [f"{host}:{CKAN_RESPONDER_IP}" for host in CKAN_ALIASES]
        tail = [image_tag(server.service), *server.launch]
        assert launch.args[-len(tail) :] == tail
        assert len(ensured) == 1
        assert removed == []
        name = _value_after(launch.args, "--name")

    assert removed == [name]


def test_two_ckan_provisioners_of_one_server_are_open_at_once(monkeypatch: pytest.MonkeyPatch):
    def noop_ensure() -> None:
        pass

    def noop_rm(name: str) -> None:
        pass

    monkeypatch.setattr(nuisance_backends, "ensure_ckan_responder", noop_ensure)
    monkeypatch.setattr(nuisance_backends, "ckan_rm", noop_rm)
    server = _a_server()

    with ckan_provisioner(server), ckan_provisioner(server):
        pass


def test_the_contextforge_fixture_is_accepted_by_the_registry():
    backend = BackendFixture(
        provisioner="contextforge",
        image=CONTEXTFORGE_RESPONDER_IMAGE,
        network=CONTEXTFORGE_BRIDGE,
    )

    assert backend_problems(given.with_a_backend(_a_server(), backend), BACKENDS) == []


def test_contextforge_provisioner_wires_the_responder_and_reaps_the_server(
    monkeypatch: pytest.MonkeyPatch,
):
    ensured: list[None] = []
    removed: list[str] = []

    def record_ensure() -> None:
        ensured.append(None)

    def record_rm(name: str) -> None:
        removed.append(name)

    monkeypatch.setattr(nuisance_backends, "ensure_contextforge_responder", record_ensure)
    monkeypatch.setattr(nuisance_backends, "contextforge_rm", record_rm)
    server = _a_server()

    with contextforge_provisioner(server) as launch:
        assert _value_after(launch.args, "--network") == CONTEXTFORGE_BRIDGE
        assert _value_after(launch.args, "--user") == "65534:65534"
        assert _value_after(launch.args, "-w") == "/"
        tail = [image_tag(server.service), *server.launch]
        assert launch.args[-len(tail) :] == tail
        assert len(ensured) == 1
        assert removed == []
        name = _value_after(launch.args, "--name")

    assert removed == [name]


def test_two_contextforge_provisioners_of_one_server_are_open_at_once(
    monkeypatch: pytest.MonkeyPatch,
):
    def noop_ensure() -> None:
        pass

    def noop_rm(name: str) -> None:
        pass

    monkeypatch.setattr(nuisance_backends, "ensure_contextforge_responder", noop_ensure)
    monkeypatch.setattr(nuisance_backends, "contextforge_rm", noop_rm)
    server = _a_server()

    with contextforge_provisioner(server), contextforge_provisioner(server):
        pass


def test_the_mysql_fixture_is_accepted_by_the_registry():
    backend = BackendFixture(provisioner="mysql", image=MYSQL_IMAGE, network=MYSQL_BRIDGE)

    assert backend_problems(given.with_a_backend(_a_server(), backend), BACKENDS) == []


def test_mysql_provisioner_wires_the_pair_and_reaps_the_server(monkeypatch: pytest.MonkeyPatch):
    ensured: list[None] = []
    removed: list[str] = []

    def record_ensure() -> None:
        ensured.append(None)

    def record_rm(name: str) -> None:
        removed.append(name)

    monkeypatch.setattr(nuisance_backends, "ensure_mysql", record_ensure)
    monkeypatch.setattr(nuisance_backends, "mysql_rm", record_rm)
    server = _a_server()

    with mysql_provisioner(server) as launch:
        assert _value_after(launch.args, "--network") == MYSQL_BRIDGE
        assert _value_after(launch.args, "--user") == "65534:65534"
        assert _value_after(launch.args, "-w") == "/"
        tail = [image_tag(server.service), *server.launch]
        assert launch.args[-len(tail) :] == tail
        assert len(ensured) == 1
        assert removed == []
        name = _value_after(launch.args, "--name")

    assert removed == [name]


def test_two_mysql_provisioners_of_one_server_are_open_at_once(monkeypatch: pytest.MonkeyPatch):
    def noop_ensure() -> None:
        pass

    def noop_rm(name: str) -> None:
        pass

    monkeypatch.setattr(nuisance_backends, "ensure_mysql", noop_ensure)
    monkeypatch.setattr(nuisance_backends, "mysql_rm", noop_rm)
    server = _a_server()

    with mysql_provisioner(server), mysql_provisioner(server):
        pass
