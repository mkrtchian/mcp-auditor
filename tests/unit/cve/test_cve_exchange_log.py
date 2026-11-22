from evals.cve.exchange_log import ExchangeLog
from mcp_auditor.domain.models import ToolResponse
from tests.fakes.mcp_client import FakeMCPClient


async def test_the_exchange_log_passes_response_through_and_records_the_exchange():
    flag_response = ToolResponse(content="the flag")
    client = FakeMCPClient(tools=[], responses={"git_diff_staged": flag_response})
    recorder = ExchangeLog(client)

    response = await recorder.call_tool("git_diff_staged", {"repo_path": "/work/secret"})

    assert response is flag_response
    assert recorder.exchanges == [("git_diff_staged", {"repo_path": "/work/secret"}, flag_response)]


async def test_the_exchange_log_keeps_the_calls_in_order():
    client = FakeMCPClient(tools=[])
    recorder = ExchangeLog(client)

    await recorder.call_tool("first", {"a": 1})
    await recorder.call_tool("second", {"b": 2})

    assert [(name, args) for name, args, _ in recorder.exchanges] == [
        ("first", {"a": 1}),
        ("second", {"b": 2}),
    ]


async def test_the_exchange_log_forwards_ping_and_relaunch_and_records_neither():
    client = FakeMCPClient(tools=[], ping_answers=[False], relaunch_answers=[False])
    recorder = ExchangeLog(client)

    pinged = await recorder.ping()
    relaunched = await recorder.relaunch()

    assert (pinged, relaunched) == (False, False)
    assert (client.pings, client.relaunches) == (1, 1)
    assert recorder.exchanges == []


async def test_the_exchange_log_keeps_the_count_of_exchanges_at_each_relaunch():
    client = FakeMCPClient(tools=[], relaunch_answers=[True, False])
    recorder = ExchangeLog(client)

    await recorder.call_tool("first", {})
    await recorder.relaunch()
    await recorder.call_tool("second", {})
    await recorder.call_tool("third", {})
    await recorder.relaunch()

    assert recorder.relaunched_after == [1, 3]
