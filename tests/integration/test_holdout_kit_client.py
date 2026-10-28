import sys

from evals.holdout_kit.kit_client import KitMCPClient
from tests.integration.support.test_mcp_client_transport_given import STUB_PATH


async def test_a_server_logging_its_shutdown_to_stdout_is_left_cleanly() -> None:
    async with KitMCPClient.connect(sys.executable, [str(STUB_PATH), "noisy_shutdown"]) as client:
        response = await client.call_tool("read", {"path": "/any"})

    assert response.content == "ok"
