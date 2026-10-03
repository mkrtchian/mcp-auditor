# The MCP SDK logs data the server sent, outside the boundary `AuditedServer` redacts.
import logging
from collections.abc import Iterator
from contextlib import contextmanager

from mcp_auditor.domain.redaction import Redaction

# `mcp/client/session.py` names its logger "client", not after its module.
_SDK_LOGGERS_REDACTED = ("", "client")
_SDK_LOGGER_SILENCED = "mcp.client.stdio"


@contextmanager
def redacted_sdk_logging(redaction: Redaction) -> Iterator[None]:
    """Only while a value is relayed, so that an audit without one keeps every diagnostic."""
    if not redaction.active:
        yield
        return
    # A filter on a logger sees only the records created on it, never those propagated
    # from a child, so each logger that quotes the server carries its own.
    redacted = [logging.getLogger(name) for name in _SDK_LOGGERS_REDACTED]
    log_filter = RedactingFilter(redaction)
    silenced = logging.getLogger(_SDK_LOGGER_SILENCED)
    previous_level = silenced.level
    for logger in redacted:
        logger.addFilter(log_filter)
    # Its exception quotes the raw line the server wrote.
    silenced.setLevel(logging.CRITICAL)
    try:
        yield
    finally:
        silenced.setLevel(previous_level)
        for logger in redacted:
            logger.removeFilter(log_filter)


class RedactingFilter(logging.Filter):
    def __init__(self, redaction: Redaction) -> None:
        super().__init__()
        self._redaction = redaction

    def filter(self, record: logging.LogRecord) -> bool:
        record.msg = self._redaction.text(record.getMessage())
        record.args = None
        if record.exc_info:
            traceback = logging.Formatter().formatException(record.exc_info)
            record.exc_text = self._redaction.text(traceback)
        return True
