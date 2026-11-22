"""The benign call retries a launch or connection that fails, never an answer or a teardown, and
hands whether the server answered a ping to its callback. `drop_failing_servers` gives a server
whose benign call fails a second pass, alone, once every first pass has finished, with its backend
containers removed before it, and drops it only when that pass fails too."""

import pytest

import tests.unit.nuisance.support.test_nuisance_vetting_given as given
import tests.unit.support.admission_mutations as mutations
from evals.cve.backends.doris import DORIS_CONTAINER
from evals.cve.nuisance.admission.admission import AdmittedServer
from evals.cve.nuisance.results import NotRunCause, NotRunServer
from evals.cve.nuisance.vetting import drop_failing_servers
from mcp_auditor.domain.container_name import declared_container_name
from mcp_auditor.domain.models import ToolResponse


async def test_a_benign_call_whose_connection_fails_twice_then_answers_passes():
    launches = given.launches_failing(failing=2)

    reason = await given.a_benign_call_on(launches)(given.a_server())

    assert reason is None
    assert launches.launches == 3


async def test_a_benign_call_whose_connection_fails_three_times_keeps_the_last_reason():
    launches = given.launches_failing(failing=3)

    reason = await given.a_benign_call_on(launches)(given.a_server())

    assert reason == "failed to connect for the benign call: TimeoutError"
    assert launches.launches == 3


async def test_a_benign_call_launches_a_named_container():
    launches = given.launches_failing(failing=0)

    await given.a_benign_call_on(launches)(given.a_server())

    (connected,) = launches.connected
    assert isinstance(declared_container_name(connected.args), str)


async def test_a_benign_call_answering_with_an_error_is_not_retried():
    answer = ToolResponse(content="denied", is_error=True)
    launches = given.launches_failing(failing=0, answer=answer)

    reason = await given.a_benign_call_on(launches)(given.a_server())

    assert reason == f"benign call of {given.COUNTED_TOOL!r} returned an error: denied"
    assert launches.launches == 1


async def test_a_benign_call_whose_teardown_fails_once_connected_is_not_retried():
    launches = given.launches_failing(failing=0, teardown_fails=True)

    reason = await given.a_benign_call_on(launches)(given.a_server())

    assert reason == "failed to connect for the benign call: OSError"
    assert launches.launches == 1


@pytest.mark.parametrize("answered", [True, False])
async def test_a_benign_call_hands_whether_the_server_answered_the_ping_to_its_callback(
    answered: bool,
):
    launches = given.launches_failing(failing=2, ping_answer=answered)
    answers: list[tuple[AdmittedServer, bool]] = []
    benign_call = given.a_benign_call_on(
        launches, lambda server, ping: answers.append((server, ping))
    )

    reason = await benign_call(given.a_server())

    assert reason is None
    assert answers == [(given.a_server(), answered)]


async def test_a_server_that_never_connects_hands_no_ping_answer_to_the_callback():
    launches = given.launches_failing(failing=3)
    answers: list[tuple[AdmittedServer, bool]] = []
    benign_call = given.a_benign_call_on(
        launches, lambda server, ping: answers.append((server, ping))
    )

    await benign_call(given.a_server())

    assert answers == []


async def test_a_server_answering_its_second_pass_survives_with_its_first_pass_reason():
    server = given.a_server("npm:flaky")
    vet = given.ScriptedVet({"npm:flaky": ["boom", None]})

    result = await drop_failing_servers([server], vet.benign_call, vet.host)

    assert result.surviving == [server]
    assert result.second_pass == {"npm:flaky": "boom"}
    assert result.not_run == []


async def test_a_server_failing_both_passes_is_not_run_with_its_second_reason():
    vet = given.ScriptedVet({"npm:broken": ["first", "second"]})

    result = await drop_failing_servers([given.a_server("npm:broken")], vet.benign_call, vet.host)

    assert result.not_run == [NotRunServer("npm:broken", "second", NotRunCause.BENIGN_CALL_FAILED)]
    assert result.second_pass == {}
    assert result.surviving == []


async def test_a_server_answering_its_first_pass_is_called_once_and_its_backend_left_running():
    ckan = mutations.on_the_ckan_backend(given.a_server("npm:ckan"))
    vet = given.ScriptedVet({"npm:plain": ["boom", None]}, {given.CKAN_TAG: ["ckan_front"]})

    await drop_failing_servers([ckan, given.a_server("npm:plain")], vet.benign_call, vet.host)

    assert vet.calls.count("npm:ckan") == 1
    assert vet.removed == []


async def test_the_ckan_containers_of_a_failing_server_are_removed_right_before_its_second_call():
    ckan = mutations.on_the_ckan_backend(given.a_server("npm:ckan"))
    vet = given.ScriptedVet({"npm:ckan": ["boom", None]}, {given.CKAN_TAG: ["ckan_front"]})

    await drop_failing_servers([ckan], vet.benign_call, vet.host)

    assert vet.events == [("call", "npm:ckan"), ("removed", "ckan_front"), ("call", "npm:ckan")]


async def test_the_doris_cluster_of_a_failing_server_is_removed_right_before_its_second_call():
    doris = mutations.with_the_registered_backend(given.a_server("PyPI:d"), "doris")
    vet = given.ScriptedVet({"PyPI:d": ["boom", None]})

    await drop_failing_servers([doris], vet.benign_call, vet.host)

    assert vet.events == [("call", "PyPI:d"), ("removed", DORIS_CONTAINER), ("call", "PyPI:d")]


async def test_a_failing_server_with_no_backend_removes_nothing_before_its_second_call():
    vet = given.ScriptedVet({"npm:plain": ["boom", None]}, {given.CKAN_TAG: ["ckan_front"]})

    await drop_failing_servers([given.a_server("npm:plain")], vet.benign_call, vet.host)

    assert vet.events == [("call", "npm:plain"), ("call", "npm:plain")]


async def test_every_second_pass_comes_after_every_first_pass_the_solo_servers_included():
    servers = [given.a_server(given.SOLO_SERVER), given.a_server("npm:plain")]
    vet = given.ScriptedVet({given.SOLO_SERVER: ["boom", None], "npm:plain": ["boom", None]})

    await drop_failing_servers(servers, vet.benign_call, vet.host)

    assert vet.calls == ["npm:plain", given.SOLO_SERVER, given.SOLO_SERVER, "npm:plain"]


async def test_the_surviving_servers_keep_their_order_with_a_second_pass_server_among_them():
    servers = [given.a_server(package) for package in ("npm:a", "npm:flaky", "npm:c")]
    vet = given.ScriptedVet({"npm:flaky": ["boom", None]})

    result = await drop_failing_servers(servers, vet.benign_call, vet.host)

    assert result.surviving == servers
