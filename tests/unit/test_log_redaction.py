import io
import logging

import tests.unit.support.test_log_redaction_given as given
from mcp_auditor.adapters.log_redaction import RedactingFilter, redacted_sdk_logging
from mcp_auditor.domain.redaction import Redaction, marker

REDACTION = Redaction({"TOKEN": given.VALUE})


def test_a_record_and_its_exception_are_formatted_with_the_marker() -> None:
    logger = logging.getLogger("test_log_redaction.filtered")
    logger.propagate = False
    output = io.StringIO()
    logger.addHandler(logging.StreamHandler(output))
    logger.addFilter(RedactingFilter(REDACTION))

    try:
        raise ValueError(f"server sent {given.VALUE}")
    except ValueError:
        logger.exception("received %s", given.VALUE)

    formatted = output.getvalue()
    assert formatted.count(marker("TOKEN")) == 2
    assert given.VALUE not in formatted


def test_an_active_redaction_masks_the_value_and_silences_the_stdio_logger() -> None:
    with given.sdk_output() as outputs, redacted_sdk_logging(REDACTION):
        given.server_data_logged()

    assert marker("TOKEN") in outputs["client"].getvalue()
    assert outputs["mcp.client.stdio"].getvalue() == ""
    assert all(given.VALUE not in output.getvalue() for output in outputs.values())


def test_an_active_redaction_is_undone_on_exit() -> None:
    with given.sdk_output() as outputs:
        with redacted_sdk_logging(REDACTION):
            pass
        given.server_data_logged()

    assert all(given.VALUE in output.getvalue() for output in outputs.values())


def test_an_inactive_redaction_leaves_every_record_as_logged() -> None:
    with given.sdk_output() as outputs, redacted_sdk_logging(Redaction.none()):
        given.server_data_logged()

    assert all(given.VALUE in output.getvalue() for output in outputs.values())
