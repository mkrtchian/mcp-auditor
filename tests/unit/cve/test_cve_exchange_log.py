from evals.cve.exchange_log import ExchangeLog
from mcp_auditor.domain.models import ToolResponse
from tests.fakes.mcp_client import FakeMCPClient


async def test_the_exchange_log_passes_response_through_and_records_the_exchange():
    flag_response = ToolResponse(content="the flag")
    client = FakeMCPClient(tools=[], responses={"git_diff_staged": flag_response})
    exchange_log = ExchangeLog(client)

    response = await exchange_log.call_tool("git_diff_staged", {"repo_path": "/work/secret"})

    assert response is flag_response
    assert exchange_log.exchanges == [
        ("git_diff_staged", {"repo_path": "/work/secret"}, flag_response)
    ]


async def test_the_exchange_log_keeps_the_calls_in_order():
    client = FakeMCPClient(tools=[])
    exchange_log = ExchangeLog(client)

    await exchange_log.call_tool("first", {"a": 1})
    await exchange_log.call_tool("second", {"b": 2})

    assert [(name, args) for name, args, _ in exchange_log.exchanges] == [
        ("first", {"a": 1}),
        ("second", {"b": 2}),
    ]


async def test_the_exchange_log_forwards_ping_and_relaunch_and_records_neither():
    client = FakeMCPClient(tools=[], ping_answers=[False], relaunch_answers=[False])
    exchange_log = ExchangeLog(client)

    pinged = await exchange_log.ping()
    relaunched = await exchange_log.relaunch()

    assert (pinged, relaunched) == (False, False)
    assert (client.pings, client.relaunches) == (1, 1)
    assert exchange_log.exchanges == []


async def test_the_exchange_log_keeps_the_count_of_exchanges_at_each_relaunch():
    client = FakeMCPClient(tools=[], relaunch_answers=[True, False])
    exchange_log = ExchangeLog(client)

    await exchange_log.call_tool("first", {})
    await exchange_log.relaunch()
    await exchange_log.call_tool("second", {})
    await exchange_log.call_tool("third", {})
    await exchange_log.relaunch()

    assert exchange_log.relaunched_after == [1, 3]
