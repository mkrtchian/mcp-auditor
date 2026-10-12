from evals.cve_recording_client import RecordingClient
from mcp_auditor.domain import ToolResponse
from tests.fakes.mcp_client import FakeMCPClient


async def test_recording_client_passes_response_through_and_records_the_exchange():
    flag_response = ToolResponse(content="the flag")
    client = FakeMCPClient(tools=[], responses={"git_diff_staged": flag_response})
    recorder = RecordingClient(client)

    response = await recorder.call_tool("git_diff_staged", {"repo_path": "/work/secret"})

    assert response is flag_response
    assert recorder.exchanges == [("git_diff_staged", {"repo_path": "/work/secret"}, flag_response)]


async def test_recording_client_keeps_the_calls_in_order():
    client = FakeMCPClient(tools=[])
    recorder = RecordingClient(client)

    await recorder.call_tool("first", {"a": 1})
    await recorder.call_tool("second", {"b": 2})

    assert [(name, args) for name, args, _ in recorder.exchanges] == [
        ("first", {"a": 1}),
        ("second", {"b": 2}),
    ]
