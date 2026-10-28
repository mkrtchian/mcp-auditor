import pytest
from langchain_core.exceptions import (
    ModelAPIError,
    ModelAuthenticationError,
    ModelConnectionError,
    ModelNotFoundError,
    ModelPermissionDeniedError,
    ModelTimeoutError,
)
from mcp.shared.exceptions import McpError
from mcp.types import ErrorData

from evals.provider_errors import ProviderErrorKind, classify, describe_provider_error
from tests.unit.support import test_llm_throttling_given as billing
from tests.unit.support import test_provider_errors_given as given

FATAL = ProviderErrorKind.FATAL
TRANSIENT = ProviderErrorKind.TRANSIENT


@pytest.mark.parametrize(
    "error",
    [
        given.an_openai_billing_limit(),
        billing.an_anthropic_billing_error(),
        billing.an_anthropic_spend_limit_reached(),
        billing.an_anthropic_spend_cap_reached(),
        billing.an_anthropic_credit_balance_too_low(),
    ],
)
def test_a_billing_limit_is_fatal(error: Exception):
    assert classify(error) is FATAL


@pytest.mark.parametrize(
    "error",
    [
        ModelAuthenticationError("bad key"),
        ModelPermissionDeniedError("no access"),
        ModelNotFoundError("no such model"),
    ],
)
def test_an_authentication_permission_or_not_found_error_is_fatal(error: Exception):
    assert classify(error) is FATAL


@pytest.mark.parametrize("status", [401, 402, 403, 404])
def test_an_unmapped_client_status_that_no_retry_cures_is_fatal(status: int):
    assert classify(given.AnUnmappedError(status_code=status)) is FATAL


def test_a_status_carried_as_a_code_on_the_error_is_read():
    assert classify(given.AnUnmappedError(code=401)) is FATAL


def test_a_status_carried_as_a_code_on_the_error_it_is_raised_from_is_read():
    assert classify(given.a_google_error_caused_by_status(402)) is FATAL


@pytest.mark.parametrize(
    "error",
    [
        given.AnUnmappedError(status_code=500),
        given.AnUnmappedError(status_code=529),
        given.AnUnmappedError(status_code=400),
        billing.an_anthropic_invalid_request(),
        ModelAPIError("overloaded"),
        ModelConnectionError("connection reset"),
        ModelTimeoutError("read timeout"),
    ],
)
def test_any_other_provider_error_is_transient(error: Exception):
    assert classify(error) is TRANSIENT


@pytest.mark.parametrize(
    "error",
    [
        TimeoutError("list_tools timed out"),
        McpError(ErrorData(code=-32000, message="Connection closed")),
        KeyError("audit_report"),
        given.AnUnmappedError(code={"reason": "not hashable"}),
    ],
)
def test_an_error_of_the_server_or_the_graph_is_no_provider_error(error: Exception):
    assert classify(error) is None


def test_a_provider_error_is_described_by_its_type_and_status_without_its_message():
    described = describe_provider_error(given.AnUnmappedError(status_code=503))

    assert "AnUnmappedError" in described
    assert "503" in described
    assert "secret" not in described


def test_a_provider_error_with_no_status_is_described_by_its_type():
    assert describe_provider_error(ModelConnectionError("secret")) == "ModelConnectionError"
