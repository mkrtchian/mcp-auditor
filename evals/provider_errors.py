"""Which exception out of an audit's graph is the model provider's, and whether a run can go on.

A provider error is a `ModelError` (the integrations map their HTTP errors onto its subclasses),
or failing that an error carrying an integer status, as `status_code` or as `code` on itself or
on the error it is raised from (langchain_google_genai raises an unmapped client status that way).
Fatal when no retry and no other target can cure it: authentication, permission, model not found
and billing. Every other provider error is transient. The graph's own failures (a server that
died under `list_tools`, a bug) are no provider error and stay a launch failure."""

from collections.abc import Awaitable, Generator
from contextlib import contextmanager
from enum import Enum

from langchain_core.exceptions import (
    ModelAuthenticationError,
    ModelError,
    ModelNotFoundError,
    ModelPermissionDeniedError,
)

from mcp_auditor.adapters.llm_throttling import is_billing_limit


class ProviderErrorKind(Enum):
    FATAL = "fatal"
    TRANSIENT = "transient"


class ProviderFatal(Exception):
    """A provider error no retry cures, which stops the whole run."""

    def __init__(self, cause: BaseException) -> None:
        super().__init__(describe_provider_error(cause))
        self.cause = cause


class AuditFailed(Exception):
    """A provider error out of an audit's graph, kept apart from the launch failures."""

    def __init__(self, cause: BaseException, kind: ProviderErrorKind) -> None:
        super().__init__(describe_provider_error(cause))
        self.cause = cause
        self.kind = kind


_FATAL_MODEL_ERRORS = (ModelAuthenticationError, ModelPermissionDeniedError, ModelNotFoundError)
_FATAL_STATUSES = frozenset({401, 402, 403, 404})


def classify(error: BaseException) -> ProviderErrorKind | None:
    if isinstance(error, _FATAL_MODEL_ERRORS) or is_billing_limit(error):
        return ProviderErrorKind.FATAL
    status = _status_of(error)
    if status is None and not isinstance(error, ModelError):
        return None
    return ProviderErrorKind.FATAL if status in _FATAL_STATUSES else ProviderErrorKind.TRANSIENT


def describe_provider_error(error: BaseException) -> str:
    """The error's type and status, never its message, which may quote the prompt."""
    status = _status_of(error)
    name = type(error).__name__
    return name if status is None else f"{name}, status {status}"


async def classified[T](call: Awaitable[T]) -> T:
    """The call's result, a provider error it raises turned into `AuditFailed`."""
    try:
        return await call
    except Exception as exc:
        kind = classify(exc)
        if kind is None:
            raise
        raise AuditFailed(exc, kind) from exc


@contextmanager
def audit_failures_unwrapped() -> Generator[None]:
    """Lets an `AuditFailed` out bare. It crosses the MCP client wrapped in nested exception
    groups, or bare from a server noisy at shutdown, and `except*` reads both shapes."""
    try:
        yield
    except* AuditFailed as group:
        # A `from` would overwrite the leaf's own cause, the provider error.
        raise _first_leaf(group)  # noqa: B904


def _first_leaf(group: BaseExceptionGroup[AuditFailed]) -> AuditFailed:
    leaf: AuditFailed | BaseExceptionGroup[AuditFailed] = group
    while isinstance(leaf, BaseExceptionGroup):
        leaf = leaf.exceptions[0]
    return leaf


def _status_of(error: BaseException) -> int | None:
    for status in (
        getattr(error, "status_code", None),
        getattr(error, "code", None),
        getattr(error.__cause__, "code", None),
    ):
        if isinstance(status, int) and not isinstance(status, bool):
            return status
    return None
