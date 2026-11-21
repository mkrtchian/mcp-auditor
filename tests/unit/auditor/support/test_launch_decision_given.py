from mcp_auditor.domain.relayed_environment import RelayRequest
from mcp_auditor.server_execution import LaunchContext
from tests.fakes import FakeContainerRuntime
from tests.unit.auditor.support.launch_contexts import a_context

FILESYSTEM_SERVER = "@modelcontextprotocol/server-filesystem"
TOKEN_VALUE = "a-token-long-enough"


def a_context_relaying(
    runtime: FakeContainerRuntime, name: str, *, unconfined: bool = False
) -> LaunchContext:
    return a_context(
        runtime,
        unconfined=unconfined,
        relay=RelayRequest(redacted=(name,)),
        environ={name: TOKEN_VALUE},
    )
