import pytest

import tests.unit.cve.support.test_cve_server_health_given as given
from evals.cve.exchange_log import Exchange
from evals.cve.server_health import NO_INCIDENTS, ServerHealth, health_of
from mcp_auditor.domain.server_watch import LOST_CONNECTION_RESPONSES

_NO_REPORT_INCIDENT = given.a_report_with(relaunches=0, gaps=[])


def test_healths_add_up_count_by_count():
    assert ServerHealth(2, 1, 1, 3) + ServerHealth(3, 0, 2, 0) == ServerHealth(5, 1, 3, 3)
    assert NO_INCIDENTS + ServerHealth(1, 4, 2, 5) == ServerHealth(1, 4, 2, 5)


def test_no_incidents_counts_nothing():
    assert (NO_INCIDENTS.relaunches, NO_INCIDENTS.unsent_calls) == (0, 0)
    assert NO_INCIDENTS + NO_INCIDENTS == NO_INCIDENTS


def test_the_health_reads_the_client_count_and_the_lost_connections_of_the_calls():
    calls: list[Exchange] = [("read", {}, given.ANSWERED), ("read", {}, given.LOST)]

    assert health_of(given.NoisyClient(), calls, _NO_REPORT_INCIDENT) == ServerHealth(2, 1)


def test_the_health_reads_the_relaunches_and_the_calls_not_sent_from_the_report():
    report = given.a_report_with(relaunches=2, gaps=[(3, 1), (2, 0)])

    health = health_of(object(), [], report)

    assert (health.relaunches, health.unsent_calls) == (2, 6)


def test_a_client_that_counts_no_line_reads_none():
    assert health_of(object(), [("read", {}, given.ANSWERED)], _NO_REPORT_INCIDENT) == NO_INCIDENTS


@pytest.mark.parametrize(("error_type", "content"), LOST_CONNECTION_RESPONSES)
def test_each_lost_connection_response_of_the_product_counts(error_type: str, content: str | None):
    call: Exchange = ("read", {}, given.a_response(error_type, content or ""))

    assert health_of(object(), [call], _NO_REPORT_INCIDENT).lost_connection_responses == 1


def test_a_timeout_or_another_error_is_no_lost_connection():
    calls: list[Exchange] = [
        ("read", {}, given.a_response("TimeoutError", "Tool call timed out after 2s")),
        ("read", {}, given.a_response("McpError", "Invalid params")),
    ]

    assert health_of(object(), calls, _NO_REPORT_INCIDENT) == NO_INCIDENTS
