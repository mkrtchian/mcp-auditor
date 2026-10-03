import logging

import pytest

import tests.integration.support.test_relayed_environment_given as given
from mcp_auditor.domain.redaction import marker
from mcp_auditor.domain.relayed_environment import RelayRequest

MARKER = marker(given.NAME)


async def test_a_redacted_variable_comes_back_as_the_marker() -> None:
    echo = await given.echoed_through_the_audit_boundaries(RelayRequest(redacted=(given.NAME,)))

    assert echo.response == MARKER


async def test_the_server_stderr_is_kept_redacted() -> None:
    echo = await given.echoed_through_the_audit_boundaries(RelayRequest(redacted=(given.NAME,)))

    assert MARKER in echo.stderr
    assert given.VALUE not in echo.stderr


async def test_the_sdk_logs_never_quote_a_redacted_value(
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level(logging.DEBUG, logger="mcp.client.stdio")

    await given.echoed_through_the_audit_boundaries(RelayRequest(redacted=(given.NAME,)))

    assert given.VALUE not in caplog.text
    assert not [r for r in caplog.records if r.name == "mcp.client.stdio"]
    rejected = [r for r in caplog.records if "Failed to validate notification" in r.getMessage()]
    assert rejected
    assert all(MARKER in r.getMessage() for r in rejected)


async def test_a_plain_variable_comes_back_in_the_clear() -> None:
    echo = await given.echoed_through_the_audit_boundaries(RelayRequest(plain=(given.NAME,)))

    assert echo.response == given.VALUE


async def test_without_relays_the_unparsable_line_is_still_reported(
    caplog: pytest.LogCaptureFixture,
) -> None:
    await given.echoed_through_the_audit_boundaries(RelayRequest())

    assert any(
        r.name == "mcp.client.stdio" and "Failed to parse JSONRPC message" in r.getMessage()
        for r in caplog.records
    )
