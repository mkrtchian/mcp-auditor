from evals.nuisance_fix_checks.cve_2026_53710_contextforge_sandbox import TARGET
from tests.fakes import FakeKitClient

_BLOCKED_DUNDERS = (
    "__class__",
    "__base__",
    "__subclasses__",
    "__globals__",
    "__code__",
    "__closure__",
)


async def test_escape_source_carries_no_literal_blocked_dunder_substring():
    # v1.0.1's validate_code blocks these as plain substrings of the submitted code; the escape
    # must build each dunder name at runtime rather than write it literally.
    client = FakeKitClient()
    await TARGET.exploits[0]({}, client)

    code = str(client.calls[0][1]["code"])
    for dunder in _BLOCKED_DUNDERS:
        assert dunder not in code
