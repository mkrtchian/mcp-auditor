import asyncio

import pytest

import tests.unit.support.test_throttling_given as given
from mcp_auditor.adapters.throttling import counting_throttles, install_throttle_log_handler


@pytest.fixture(autouse=True)
def handler_installed() -> None:
    install_throttle_log_handler()


async def test_an_httpx_429_is_counted_once():
    client = given.an_httpx_client_answering([429, 200])

    with counting_throttles() as tally:
        await given.calls(client, 2)

    assert tally.requests == 1


async def test_an_httpx2_429_is_counted_once():
    client = given.an_httpx2_client_answering([429, 200])

    with counting_throttles() as tally:
        await given.calls(client, 2)

    assert tally.requests == 1


async def test_a_429_outside_any_count_is_ignored():
    client = given.an_httpx2_client_answering([429])

    await given.calls(client, 1)


async def test_concurrent_counts_keep_their_own_throttles():
    async def count(statuses: list[int]) -> int:
        client = given.an_httpx_client_answering(statuses)
        with counting_throttles() as tally:
            await given.calls(client, 2)
        return tally.requests

    counts = await asyncio.gather(count([429, 429]), count([200, 200]))

    assert counts == [2, 0]


async def test_a_fireworks_retry_counts_the_throttled_response_once(
    monkeypatch: pytest.MonkeyPatch,
):
    monkeypatch.setattr(asyncio, "sleep", given.no_wait)
    model = given.a_fireworks_model_answering([429, 200])

    with counting_throttles() as tally:
        await model.ainvoke("prompt")

    assert tally.requests == 1


async def test_a_google_retry_counts_the_throttled_response(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(asyncio, "sleep", given.no_wait)
    model = given.a_google_model_answering([429, 200])

    with counting_throttles() as tally:
        answer = await model.ainvoke("prompt")

    assert tally.requests == 1
    assert answer.content == "ok"


async def test_installing_twice_counts_a_429_once():
    install_throttle_log_handler()
    client = given.an_httpx_client_answering([429])

    with counting_throttles() as tally:
        await given.calls(client, 1)

    assert tally.requests == 1
