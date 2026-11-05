import tests.unit.support.test_nuisance_admission_edits_given as edits
import tests.unit.support.test_nuisance_benign_call_given as given
from evals.nuisance_benign_call import benign_call_failure
from mcp_auditor.domain import ToolResponse
from tests.unit.support.test_nuisance_benign_call_given import (
    FIRST_TOOL,
    PREREQUISITE_TOOL,
    SECOND_TOOL,
    SERVER,
)


async def test_clean_listed_calls_holding_their_expected_text_give_no_failure():
    client = given.a_listing_client()

    reason = await benign_call_failure(SERVER, client)

    assert reason is None
    assert sorted(name for name, _ in client.calls) == sorted([FIRST_TOOL, SECOND_TOOL])


async def test_a_text_without_the_expected_text_names_the_tool_and_the_expected_text():
    answer = ToolResponse(content="File not found: agents.yaml")
    client = given.a_listing_client(responses={SECOND_TOOL: answer})

    reason = await benign_call_failure(SERVER, client)

    assert reason == (
        f"benign call of {SECOND_TOOL!r} did not return "
        f"{given.expected_text(SECOND_TOOL)!r}: File not found: agents.yaml"
    )


async def test_an_empty_text_with_an_expected_text_returned_no_text():
    client = given.a_listing_client(responses={FIRST_TOOL: ToolResponse(content="")})

    reason = await benign_call_failure(SERVER, client)

    assert reason == f"benign call of {FIRST_TOOL!r} returned no text"


async def test_an_unset_expected_text_passes_on_any_text_that_is_not_an_error():
    server = edits.with_the_first_benign_call(SERVER, expect=None)
    client = given.a_listing_client(responses={FIRST_TOOL: ToolResponse(content="")})

    reason = await benign_call_failure(server, client)

    assert reason is None


async def test_a_counted_tool_missing_from_the_listing_is_named():
    client = given.a_listing_client(tools=[FIRST_TOOL])

    reason = await benign_call_failure(SERVER, client)

    assert reason == f"counted tool {SECOND_TOOL!r} is not in the server's tools/list"
    assert client.calls == []


async def test_a_prerequisite_tool_missing_from_the_listing_is_named():
    server = given.with_a_prerequisite(SERVER)

    reason = await benign_call_failure(server, given.a_listing_client())

    assert reason == (
        f"prerequisite tool {PREREQUISITE_TOOL!r} of {FIRST_TOOL!r} "
        "is not in the server's tools/list"
    )


async def test_a_prerequisite_call_answering_an_error_names_both_tools():
    server = given.with_a_prerequisite(SERVER)
    client = given.a_listing_client(
        tools=[FIRST_TOOL, SECOND_TOOL, PREREQUISITE_TOOL],
        responses={PREREQUISITE_TOOL: ToolResponse(content="refused", is_error=True)},
    )

    reason = await benign_call_failure(server, client)

    assert reason == (
        f"prerequisite call of {PREREQUISITE_TOOL!r} before {FIRST_TOOL!r} "
        "returned an error: refused"
    )


async def test_a_tool_answering_once_its_prerequisite_ran_passes():
    client = given.ConnectingClient()

    reason = await benign_call_failure(given.with_a_prerequisite(SERVER), client)

    assert reason is None
    assert [name for name, _ in client.calls][:2] == [PREREQUISITE_TOOL, FIRST_TOOL]


async def test_the_same_tool_without_its_prerequisite_fails_on_its_text():
    reason = await benign_call_failure(SERVER, given.ConnectingClient())

    assert reason is not None
    assert "No database connection available" in reason


async def test_no_prerequisite_makes_only_the_checked_calls():
    client = given.a_listing_client(tools=[FIRST_TOOL, SECOND_TOOL, PREREQUISITE_TOOL])

    await benign_call_failure(SERVER, client)

    assert sorted(name for name, _ in client.calls) == sorted([FIRST_TOOL, SECOND_TOOL])


async def test_a_benign_call_answering_an_error_names_the_tool():
    answer = ToolResponse(content="boom", is_error=True)
    client = given.a_listing_client(responses={SECOND_TOOL: answer})

    reason = await benign_call_failure(SERVER, client)

    assert reason == f"benign call of {SECOND_TOOL!r} returned an error: boom"


async def test_a_benign_call_raising_names_the_tool():
    reason = await benign_call_failure(SERVER, given.RaisingClient(FIRST_TOOL))

    assert reason is not None
    assert FIRST_TOOL in reason


async def test_a_listing_that_raises_names_the_listing():
    reason = await benign_call_failure(SERVER, given.ListingRaisingClient())

    assert reason == "listing the server's tools failed: listing timed out"
