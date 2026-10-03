import io
import logging

from mcp_auditor.adapters.log_redaction import RedactingFilter, redacted_sdk_logging
from mcp_auditor.domain.redaction import Redaction, marker

VALUE = "s3cr3t-token-value"
REDACTION = Redaction({"TOKEN": VALUE})


def test_a_record_and_its_exception_are_formatted_with_the_marker() -> None:
    logger = logging.getLogger("test_log_redaction.filtered")
    logger.propagate = False
    output = io.StringIO()
    logger.addHandler(logging.StreamHandler(output))
    logger.addFilter(RedactingFilter(REDACTION))

    try:
        raise ValueError(f"server sent {VALUE}")
    except ValueError:
        logger.exception("received %s", VALUE)

    formatted = output.getvalue()
    assert formatted.count(marker("TOKEN")) == 2
    assert VALUE not in formatted


def test_an_inactive_redaction_leaves_the_loggers_untouched() -> None:
    root = logging.getLogger()
    stdio = logging.getLogger("mcp.client.stdio")
    filters_before, level_before = list(root.filters), stdio.level

    with redacted_sdk_logging(Redaction.none()):
        assert root.filters == filters_before
        assert stdio.level == level_before


def test_an_active_redaction_is_undone_on_exit() -> None:
    root = logging.getLogger()
    stdio = logging.getLogger("mcp.client.stdio")
    filters_before, level_before = list(root.filters), stdio.level

    with redacted_sdk_logging(REDACTION):
        assert stdio.level == logging.CRITICAL

    assert root.filters == filters_before
    assert stdio.level == level_before
