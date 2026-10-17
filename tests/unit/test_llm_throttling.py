import pytest

import tests.unit.support.test_llm_throttling_given as given
from mcp_auditor.adapters.llm_throttling import (
    Throttle,
    ThrottlePatience,
    current_breaker,
    one_audit,
    throttle_of,
)


class TestThrottleOf:
    @pytest.mark.parametrize("build", [given.an_openai_rate_limit, given.an_anthropic_rate_limit])
    def test_a_rate_limit_without_hint_is_a_throttle_without_hint(
        self, build: given.RateLimitBuilder
    ):
        assert throttle_of(build()) == Throttle(retry_after=None)

    @pytest.mark.parametrize("build", [given.an_openai_rate_limit, given.an_anthropic_rate_limit])
    def test_a_retry_after_in_seconds_is_the_hint(self, build: given.RateLimitBuilder):
        assert throttle_of(build({"Retry-After": "12"})) == Throttle(retry_after=12.0)

    def test_retry_after_ms_wins_over_retry_after(self):
        error = given.an_openai_rate_limit({"retry-after-ms": "1500", "Retry-After": "12"})

        assert throttle_of(error) == Throttle(retry_after=1.5)

    def test_a_retry_after_given_as_a_date_is_no_hint(self):
        error = given.an_openai_rate_limit({"Retry-After": "Wed, 21 Oct 2026 07:28:00 GMT"})

        assert throttle_of(error) == Throttle(retry_after=None)

    @pytest.mark.parametrize("build", [given.an_openai_rate_limit, given.an_anthropic_rate_limit])
    def test_a_rate_limit_the_provider_marks_not_retryable_is_no_throttle(
        self, build: given.RateLimitBuilder
    ):
        assert throttle_of(build({"x-should-retry": "false"})) is None

    def test_an_exhausted_credit_is_no_throttle(self):
        body = {"message": "You exceeded your current quota", "code": "insufficient_quota"}

        assert throttle_of(given.an_openai_rate_limit(body=body)) is None

    def test_a_google_rate_limit_reads_the_hint_of_the_error_it_is_raised_from(self):
        error = given.a_google_rate_limit({"Retry-After": "7"})

        assert throttle_of(error) == Throttle(retry_after=7.0)

    def test_a_server_error_is_no_throttle(self):
        assert throttle_of(given.an_openai_server_error()) is None

    def test_an_error_without_http_status_is_no_throttle(self):
        assert throttle_of(ValueError("boom")) is None


class TestThrottlePatience:
    def test_without_hint_the_delay_doubles_up_to_its_cap(self):
        patience = ThrottlePatience(jitter=lambda: 0.0)

        delays = [patience.next_delay(retry, None) for retry in range(5)]

        assert delays == [10.0, 20.0, 40.0, 60.0, 60.0]

    def test_a_hint_wins_over_the_growing_delay(self):
        patience = ThrottlePatience(jitter=lambda: 0.0)

        assert patience.next_delay(3, 5.0) == 5.0

    def test_a_hint_of_zero_waits_one_second(self):
        patience = ThrottlePatience(jitter=lambda: 0.0)

        assert patience.next_delay(0, 0.0) == 1.0

    def test_the_jitter_spreads_a_delay_up_to_a_quarter_upward(self):
        patience = ThrottlePatience(jitter=lambda: 1.0)

        assert patience.next_delay(1, None) == 25.0
        assert patience.next_delay(0, 8.0) == 10.0

    def test_patience_is_exhausted_once_the_next_delay_would_pass_the_bound(self):
        patience = ThrottlePatience()

        assert not patience.exhausted(250.0, 50.0)
        assert patience.exhausted(250.0, 60.0)


class TestOneAudit:
    def test_no_breaker_outside_an_audit(self):
        assert current_breaker() is None

    def test_an_audit_opens_a_closed_breaker_and_removes_it_on_exit(self):
        with one_audit() as breaker:
            assert current_breaker() is breaker
            assert breaker.tripped_by is None

        assert current_breaker() is None

    def test_the_first_trip_names_the_breaker(self):
        with one_audit() as breaker:
            breaker.trip("first")
            breaker.trip("second")

        assert breaker.tripped_by == "first"
