import logging

import pytest

import tests.unit.evals.support.missed_judgments as missed_judgments
import tests.unit.evals.support.test_session_usage_given as given
from evals.session_usage import (
    SessionThrottles,
    ThrottledAudit,
    UsageBreakdown,
    quiet_throttle_waits,
    raise_if_throttled,
)
from mcp_auditor.domain.model_calls import MissedCallCause
from mcp_auditor.domain.models import AuditReport, ProviderUsage


def test_session_throttles_count_each_report_and_keep_the_total():
    throttles = SessionThrottles()

    counts = [throttles.count(given.a_report_throttled(times)) for times in (2, 0)]

    assert counts == [2, 0]
    assert throttles.requests == 2


def test_session_throttles_sum_the_tokens_of_every_counted_report_a_refused_one_included():
    throttles = SessionThrottles()
    refused = missed_judgments.and_a_refused_judgment(
        given.a_report_billed(100, 10), "search", "flagged"
    )

    throttles.count(given.a_report_billed(200, 20))
    throttles.count(refused)

    assert (throttles.usage.input_tokens, throttles.usage.output_tokens) == (300, 30)


def test_session_throttles_count_a_bare_usage():
    throttles = SessionThrottles()

    counted = throttles.count_usage(ProviderUsage(input_tokens=50, throttled_requests=3))

    assert counted == 3
    assert (throttles.requests, throttles.usage.input_tokens) == (3, 50)


def test_session_throttles_count_a_report_without_a_target_billing_no_target():
    throttles = SessionThrottles()

    counted = throttles.count(given.a_report_throttled(2))

    assert counted == 2
    assert throttles.requests == 2
    assert throttles.by_target == {}


def test_session_throttles_bill_each_phase_of_a_report_to_its_target():
    throttles = SessionThrottles()

    throttles.count(given.a_report_by_phase(total=300, chain=100, judge=50), "CVE-1")

    billed = throttles.by_target["CVE-1"]
    assert (billed.total.input_tokens, billed.chain.input_tokens, billed.judge.input_tokens) == (
        300,
        100,
        50,
    )


def test_phase_usage_add_sums_each_channel():
    first = UsageBreakdown.from_report(given.a_report_by_phase(total=300, chain=100, judge=50))
    second = UsageBreakdown.from_report(given.a_report_by_phase(total=30, chain=10, judge=5))

    summed = first.add(second)

    assert (summed.total.input_tokens, summed.chain.input_tokens, summed.judge.input_tokens) == (
        330,
        110,
        55,
    )


def test_a_report_holding_a_throttled_judgment_raises_naming_it():
    clean = AuditReport(server_command="test", tool_reports=[], provider_usage=ProviderUsage())
    report = missed_judgments.and_a_missed_judgment(
        clean, "search", MissedCallCause.PROVIDER_THROTTLED, "300 s waited"
    )

    with pytest.raises(ThrottledAudit, match="search: judgment, 300 s waited"):
        raise_if_throttled(report)


def test_a_report_holding_only_refused_unreadable_or_too_long_steps_does_not_raise():
    clean = AuditReport(server_command="test", tool_reports=[], provider_usage=ProviderUsage())
    refused = missed_judgments.and_a_refused_judgment(
        clean, "search", "flagged by the usage policy"
    )
    unreadable = missed_judgments.and_a_missed_judgment(
        refused, "search", MissedCallCause.UNREADABLE_ANSWER, "no answer matched"
    )
    report = missed_judgments.and_a_missed_judgment(
        unreadable, "search", MissedCallCause.PROMPT_TOO_LONG, "rejected as too long"
    )

    raise_if_throttled(report)


def test_quiet_throttle_waits_drops_a_wait_warning_and_keeps_an_error(
    caplog: pytest.LogCaptureFixture, throttling_logger: logging.Logger
):
    quiet_throttle_waits()
    throttling_logger.warning("waiting 10 s (retry 1)")
    throttling_logger.error("something broke")

    assert [record.getMessage() for record in caplog.records] == ["something broke"]


@pytest.fixture
def throttling_logger():
    logger = logging.getLogger("mcp_auditor.throttling")
    level = logger.level
    yield logger
    logger.setLevel(level)
