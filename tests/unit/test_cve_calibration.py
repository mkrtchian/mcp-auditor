import evals.run_cve_benchmark as bench
from mcp_auditor.domain import ToolResponse
from tests.fakes.mcp_client import FakeMCPClient


async def test_recording_client_passes_response_through_and_records_the_exchange():
    flag_response = ToolResponse(content="the flag")
    client = FakeMCPClient(tools=[], responses={"git_diff_staged": flag_response})
    recorder = bench.RecordingClient(client)

    response = await recorder.call_tool("git_diff_staged", {"repo_path": "/work/secret"})

    assert response is flag_response
    assert recorder.exchanges == [
        ("git_diff_staged", {"repo_path": "/work/secret"}, flag_response)
    ]
