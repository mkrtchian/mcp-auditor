import pytest

import tests.unit.support.test_nuisance_admission_given as given
from evals import nuisance_backends
from evals.doris_backend import DORIS_BRIDGE, DORIS_IMAGE
from evals.nuisance_admission import AdmittedServer, BackendFixture
from evals.nuisance_backends import BACKENDS, backend_problems, doris_provisioner
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
