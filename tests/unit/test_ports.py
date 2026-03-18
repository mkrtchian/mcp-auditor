# The real value here is the pyright check during CI, not the runtime assertions.

from mcp_auditor.domain import LLMPort, MCPClientPort
from tests.fakes import FakeLLM, FakeMCPClient


def test_fake_mcp_client_satisfies_port() -> None:
    client: MCPClientPort = FakeMCPClient(tools=[])
    assert client is not None


def test_fake_llm_satisfies_port() -> None:
    llm: LLMPort = FakeLLM(responses=[])
    assert llm is not None
