import pytest

import tests.unit.support.test_nuisance_admission_given as given
from evals import nuisance_provisioners
from evals.apify_backend import (
    APIFY_BENIGN_HOST,
    APIFY_BRIDGE,
    APIFY_RESPONDER_IMAGE,
    APIFY_RESPONDER_IP,
)
from evals.atlassian_backend import (
    ATLASSIAN_BRIDGE,
    ATLASSIAN_RESPONDER_IMAGE,
    ATLASSIAN_RESPONDER_IP,
)
from evals.jenkins_backend import JENKINS_BRIDGE, JENKINS_RESPONDER_IMAGE
from evals.nuisance_admission import AdmittedServer, BackendFixture
from evals.nuisance_backends import BACKENDS, backend_problems
from evals.nuisance_images import image_tag
from evals.nuisance_provisioners import (
    apify_provisioner,
    atlassian_provisioner,
    jenkins_provisioner,
)


def _value_after(args: list[str], flag: str) -> str:
    return args[args.index(flag) + 1]


def _a_server() -> AdmittedServer:
    return given.an_admission().servers[0]


def test_the_atlassian_fixture_is_accepted_by_the_registry():
    backend = BackendFixture(
        provisioner="atlassian", image=ATLASSIAN_RESPONDER_IMAGE, network=ATLASSIAN_BRIDGE
    )

    assert backend_problems(given.with_a_backend(_a_server(), backend), BACKENDS) == []


def test_atlassian_provisioner_wires_the_responder_and_reaps_the_server(
    monkeypatch: pytest.MonkeyPatch,
):
    ensured: list[None] = []
    removed: list[str] = []

    def record_ensure() -> None:
        ensured.append(None)

    def record_rm(name: str) -> None:
        removed.append(name)

    monkeypatch.setattr(nuisance_provisioners, "ensure_atlassian_responder", record_ensure)
    monkeypatch.setattr(nuisance_provisioners, "atlassian_rm", record_rm)
    server = _a_server()

    with atlassian_provisioner(server) as launch:
        assert _value_after(launch.args, "--network") == ATLASSIAN_BRIDGE
        assert _value_after(launch.args, "--user") == "65534:65534"
        assert _value_after(launch.args, "-w") == "/"
        assert f"JIRA_URL=http://{ATLASSIAN_RESPONDER_IP}" in launch.args
        tail = [image_tag(server.service), *server.launch]
        assert launch.args[-len(tail) :] == tail
        assert len(ensured) == 1
        assert removed == []
        name = _value_after(launch.args, "--name")

    assert removed == [name]


def test_two_atlassian_provisioners_of_one_server_are_open_at_once(
    monkeypatch: pytest.MonkeyPatch,
):
    def noop_ensure() -> None:
        pass

    def noop_rm(name: str) -> None:
        pass

    monkeypatch.setattr(nuisance_provisioners, "ensure_atlassian_responder", noop_ensure)
    monkeypatch.setattr(nuisance_provisioners, "atlassian_rm", noop_rm)
    server = _a_server()

    with atlassian_provisioner(server), atlassian_provisioner(server):
        pass


def test_the_apify_fixture_is_accepted_by_the_registry():
    backend = BackendFixture(provisioner="apify", image=APIFY_RESPONDER_IMAGE, network=APIFY_BRIDGE)

    assert backend_problems(given.with_a_backend(_a_server(), backend), BACKENDS) == []


def test_apify_provisioner_wires_the_responder_and_reaps_the_server(
    monkeypatch: pytest.MonkeyPatch,
):
    ensured: list[None] = []
    removed: list[str] = []

    def record_ensure() -> None:
        ensured.append(None)

    def record_rm(name: str) -> None:
        removed.append(name)

    monkeypatch.setattr(nuisance_provisioners, "ensure_apify_responder", record_ensure)
    monkeypatch.setattr(nuisance_provisioners, "apify_rm", record_rm)
    server = _a_server()

    with apify_provisioner(server) as launch:
        assert _value_after(launch.args, "--network") == APIFY_BRIDGE
        assert _value_after(launch.args, "--user") == "65534:65534"
        assert _value_after(launch.args, "-w") == "/"
        assert f"{APIFY_BENIGN_HOST}:{APIFY_RESPONDER_IP}" in launch.args
        tail = [image_tag(server.service), *server.launch]
        assert launch.args[-len(tail) :] == tail
        assert len(ensured) == 1
        assert removed == []
        name = _value_after(launch.args, "--name")

    assert removed == [name]


def test_two_apify_provisioners_of_one_server_are_open_at_once(
    monkeypatch: pytest.MonkeyPatch,
):
    def noop_ensure() -> None:
        pass

    def noop_rm(name: str) -> None:
        pass

    monkeypatch.setattr(nuisance_provisioners, "ensure_apify_responder", noop_ensure)
    monkeypatch.setattr(nuisance_provisioners, "apify_rm", noop_rm)
    server = _a_server()

    with apify_provisioner(server), apify_provisioner(server):
        pass


def test_the_jenkins_fixture_is_accepted_by_the_registry():
    backend = BackendFixture(
        provisioner="jenkins", image=JENKINS_RESPONDER_IMAGE, network=JENKINS_BRIDGE
    )

    assert backend_problems(given.with_a_backend(_a_server(), backend), BACKENDS) == []


def test_jenkins_provisioner_wires_the_responder_and_reaps_the_server(
    monkeypatch: pytest.MonkeyPatch,
):
    ensured: list[None] = []
    removed: list[str] = []

    def record_ensure() -> None:
        ensured.append(None)

    def record_rm(name: str) -> None:
        removed.append(name)

    monkeypatch.setattr(nuisance_provisioners, "ensure_jenkins_responder", record_ensure)
    monkeypatch.setattr(nuisance_provisioners, "jenkins_rm", record_rm)
    server = _a_server()

    with jenkins_provisioner(server) as launch:
        assert _value_after(launch.args, "--network") == JENKINS_BRIDGE
        assert _value_after(launch.args, "--user") == "65534:65534"
        assert _value_after(launch.args, "-w") == "/"
        tail = [image_tag(server.service), *server.launch]
        assert launch.args[-len(tail) :] == tail
        assert len(ensured) == 1
        assert removed == []
        name = _value_after(launch.args, "--name")

    assert removed == [name]


def test_two_jenkins_provisioners_of_one_server_are_open_at_once(
    monkeypatch: pytest.MonkeyPatch,
):
    def noop_ensure() -> None:
        pass

    def noop_rm(name: str) -> None:
        pass

    monkeypatch.setattr(nuisance_provisioners, "ensure_jenkins_responder", noop_ensure)
    monkeypatch.setattr(nuisance_provisioners, "jenkins_rm", noop_rm)
    server = _a_server()

    with jenkins_provisioner(server), jenkins_provisioner(server):
        pass
