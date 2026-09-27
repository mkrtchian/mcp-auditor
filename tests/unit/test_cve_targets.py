from collections.abc import Awaitable, Callable

import pytest

from evals.cve_calibration import RecordingClient
from evals.cve_grammar import is_aimed
from evals.cve_targets import CVE_TARGETS, CVETarget
from evals.cve_units import Unit, unit_of_exchanges
from mcp_auditor.domain.ports import MCPClientPort
from tests.fakes.mcp_client import FakeMCPClient

SSRF_TARGET = next(target for target in CVE_TARGETS if target.cve_id == "CVE-2025-65513")


@pytest.mark.parametrize("target", CVE_TARGETS, ids=[target.cve_id for target in CVE_TARGETS])
async def test_the_exploit_reads_as_aimed_and_the_benign_call_does_not(target: CVETarget):
    exploit = await _recorded(target.exploit)
    benign = await _recorded(target.benign)

    assert is_aimed(exploit, target)
    assert not is_aimed(benign, target)


@pytest.mark.parametrize(
    "url",
    [
        "http://127.0.0.1/",
        "http://127.1.2.3:8080/admin",
        "http://127.1/",
        "http://127.0.1:8080/admin",
        "http://localhost/",
        "http://169.254.169.254/latest/meta-data/",
        "http://10.0.0.5/",
        "http://172.16.0.1/",
        "http://172.31.255.255/",
        "http://192.168.1.10/",
        "http://0.0.0.0/",
        "http://[::1]/",
        "http://[fd12:3456::1]/",
        "http://[::ffff:127.0.0.1]/",
        "http://sentinel/",
        "http://sentinel:80/flag",
    ],
)
def test_the_ssrf_aim_reads_an_internal_host_as_aimed(url: str):
    assert SSRF_TARGET.aim.search(url)


@pytest.mark.parametrize(
    "url",
    [
        "http://example.com/",
        "https://example.com/?next=http://127.0.0.1/",
        "http://172.32.0.1/",
        "http://example.invalid/",
    ],
)
def test_the_ssrf_aim_does_not_read_a_public_host_as_aimed(url: str):
    assert not SSRF_TARGET.aim.search(url)


async def _recorded(call: Callable[[MCPClientPort], Awaitable[None]]) -> Unit:
    recorder = RecordingClient(FakeMCPClient([]))
    await call(recorder)
    return unit_of_exchanges([(args, response.content) for _, args, response in recorder.exchanges])
