"""Unit coverage for evals/nuisance_fix_checks/cve_2026_53710_contextforge_sandbox.py: the
service triple of the FixCheckTarget, that the escape's call matches the AIM, that no literal
blocked dunder substring ("__class__", "__base__", "__subclasses__", "__globals__", "__code__",
"__closure__") appears in the escape's source text (the v1.0.1 validate_code check it must pass
through), and that the benign call stays clean of the exploit's own aim.
"""

from typing import Any

from evals.holdout_kit.kit_client import KitResponse, KitTool
from evals.nuisance_fix_checks.cve_2026_53710_contextforge_sandbox import TARGET

_BLOCKED_DUNDERS = (
    "__class__",
    "__base__",
    "__subclasses__",
    "__globals__",
    "__code__",
    "__closure__",
)


class _RecordingClient:
    def __init__(self) -> None:
        self.calls: list[tuple[str, dict[str, Any]]] = []

    async def list_tools(self) -> list[KitTool]:
        return []

    async def call_tool(self, name: str, args: dict[str, Any]) -> KitResponse:
        self.calls.append((name, args))
        return KitResponse("", is_error=False)


def test_service_triple_sets_no_server_patched_arm():
    assert TARGET.vulnerable_service == "contextforge-sandbox-vuln"
    assert TARGET.patched_service == "contextforge-sandbox"
    assert TARGET.server_patched_service is None


async def test_escape_source_carries_no_literal_blocked_dunder_substring():
    # v1.0.1's validate_code blocks these as plain substrings of the submitted code; the escape
    # must build each dunder name at runtime rather than write it literally.
    client = _RecordingClient()
    await TARGET.exploits[0]({}, client)

    code = str(client.calls[0][1]["code"])
    for dunder in _BLOCKED_DUNDERS:
        assert dunder not in code


async def test_exploit_calls_execute_code_with_an_argument_matching_its_aim():
    client = _RecordingClient()
    await TARGET.exploits[0]({}, client)

    assert len(client.calls) == 1
    name, arguments = client.calls[0]
    assert name == "execute_code"
    assert TARGET.aim.search(str(arguments["code"]))


async def test_benign_call_does_not_match_the_exploit_aim():
    client = _RecordingClient()
    await TARGET.benign_calls[0]({}, client)

    name, arguments = client.calls[0]
    assert name == "execute_code"
    assert not TARGET.aim.search(str(arguments["code"]))
