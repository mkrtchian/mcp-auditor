# The real value here is the pyright check during CI, not the runtime assertions.

from mcp_auditor.domain import LLMPort, MCPClientPort, ProviderUsage
from mcp_auditor.domain.ports import ProviderThrottled
from tests.fakes import FakeLLM, FakeMCPClient


def test_fake_mcp_client_satisfies_port() -> None:
    client: MCPClientPort = FakeMCPClient(tools=[])
    assert client is not None


def test_fake_llm_satisfies_port() -> None:
    llm: LLMPort = FakeLLM(responses=[])
    assert llm is not None


def test_provider_throttled_names_the_wait_and_the_provider_message() -> None:
    usage = ProviderUsage(input_tokens=10, throttled_requests=4)

    throttled = ProviderThrottled("busy", 312.4, usage)

    assert str(throttled) == (
        "the model provider throttled the request past every retry"
        " (312 s waited by the auditor): busy"
    )
    assert throttled.provider_message == "busy"
    assert throttled.waited_seconds == 312.4
    assert throttled.usage is usage
