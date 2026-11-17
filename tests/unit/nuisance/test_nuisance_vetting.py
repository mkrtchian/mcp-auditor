"""The benign call retries a launch or connection that fails, never an answer or a teardown, and
hands whether the server answered a ping to its callback."""

import pytest

import tests.unit.nuisance.support.test_nuisance_vetting_given as given
from evals.cve.nuisance.admission.admission import AdmittedServer
from evals.cve.nuisance.vetting import benign_call
from mcp_auditor.domain.models import ToolResponse


async def test_a_benign_call_whose_connection_fails_twice_then_answers_passes(
    monkeypatch: pytest.MonkeyPatch,
):
    launches = given.launches_failing(monkeypatch, failing=2)

    reason = await benign_call(given.a_server(), timeout=30)

    assert reason is None
    assert launches.launches == 3


async def test_a_benign_call_whose_connection_fails_three_times_keeps_the_last_reason(
    monkeypatch: pytest.MonkeyPatch,
):
    launches = given.launches_failing(monkeypatch, failing=3)

    reason = await benign_call(given.a_server(), timeout=30)

    assert reason == "failed to connect for the benign call: TimeoutError"
    assert launches.launches == 3


async def test_a_benign_call_answering_with_an_error_is_not_retried(
    monkeypatch: pytest.MonkeyPatch,
):
    answer = ToolResponse(content="denied", is_error=True)
    launches = given.launches_failing(monkeypatch, failing=0, answer=answer)

    reason = await benign_call(given.a_server(), timeout=30)

    assert reason == f"benign call of {given.COUNTED_TOOL!r} returned an error: denied"
    assert launches.launches == 1


async def test_a_benign_call_whose_teardown_fails_once_connected_is_not_retried(
    monkeypatch: pytest.MonkeyPatch,
):
    launches = given.launches_failing(monkeypatch, failing=0, teardown_fails=True)

    reason = await benign_call(given.a_server(), timeout=30)

    assert reason == "failed to connect for the benign call: OSError"
    assert launches.launches == 1


@pytest.mark.parametrize("answered", [True, False])
async def test_a_benign_call_hands_whether_the_server_answered_the_ping_to_its_callback(
    monkeypatch: pytest.MonkeyPatch, answered: bool
):
    given.launches_failing(monkeypatch, failing=2, ping_answer=answered)
    answers: list[tuple[AdmittedServer, bool]] = []

    reason = await benign_call(
        given.a_server(), timeout=30, on_ping=lambda server, ping: answers.append((server, ping))
    )

    assert reason is None
    assert answers == [(given.a_server(), answered)]


async def test_a_server_that_never_connects_hands_no_ping_answer_to_the_callback(
    monkeypatch: pytest.MonkeyPatch,
):
    given.launches_failing(monkeypatch, failing=3)
    answers: list[tuple[AdmittedServer, bool]] = []

    await benign_call(
        given.a_server(), timeout=30, on_ping=lambda server, ping: answers.append((server, ping))
    )

    assert answers == []
