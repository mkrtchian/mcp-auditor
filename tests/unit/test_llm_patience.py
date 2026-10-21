import asyncio
import logging

import openai
import pytest

import tests.unit.support.test_llm_patience_given as given
from mcp_auditor.adapters.llm_throttling import ThrottlePatience, one_audit
from mcp_auditor.domain.models import ProviderUsage
from mcp_auditor.domain.ports import ProviderRefusal, ProviderThrottled
from tests.fakes.chat_model import FakeChatModel

_THROTTLING_LOGGER = "mcp_auditor.throttling"


class TestPatientRetry:
    async def test_a_call_throttled_twice_then_answered_returns_the_answer(self):
        sleep = given.RecordingSleep()
        chat_model = FakeChatModel([given.a_throttle(), given.a_throttle(), given.an_answer()])
        llm = given.an_llm(chat_model, given.a_patience(sleep))

        output, usage = await llm.generate_structured("prompt", given.Output)

        assert output == given.Output(value="ok")
        assert usage == ProviderUsage(
            input_tokens=100, output_tokens=50, throttled_requests=2, largest_input_tokens=100
        )
        assert sleep.delays == [10.0, 20.0]

    async def test_each_wait_logs_one_warning(self, caplog: pytest.LogCaptureFixture):
        chat_model = FakeChatModel([given.a_throttle(), given.a_throttle(), given.an_answer()])
        llm = given.an_llm(chat_model, given.a_patience(given.RecordingSleep()))

        with caplog.at_level(logging.WARNING, logger=_THROTTLING_LOGGER):
            await llm.generate_structured("prompt", given.Output)

        assert [record.getMessage() for record in caplog.records] == [
            "the model provider is throttling requests, waiting 10 s (retry 1)",
            "the model provider is throttling requests, waiting 20 s (retry 2)",
        ]

    async def test_a_call_answered_at_once_logs_no_warning(self, caplog: pytest.LogCaptureFixture):
        llm = given.an_llm(
            FakeChatModel([given.an_answer()]), given.a_patience(given.RecordingSleep())
        )

        with caplog.at_level(logging.WARNING, logger=_THROTTLING_LOGGER):
            await llm.generate_structured("prompt", given.Output)

        assert caplog.records == []

    async def test_the_provider_hint_sets_the_wait(self):
        sleep = given.RecordingSleep()
        chat_model = FakeChatModel([given.a_throttle({"Retry-After": "3"}), given.an_answer()])
        llm = given.an_llm(chat_model, given.a_patience(sleep))

        await llm.generate_structured("prompt", given.Output)

        assert sleep.delays == [3.0]


class TestExhaustedPatience:
    async def test_a_call_throttled_past_the_bound_raises_with_every_429_counted(self):
        sleep = given.RecordingSleep()
        llm = given.an_llm(
            FakeChatModel(given.throttled_forever()), given.a_patience(sleep, max_total_wait=30.0)
        )

        with pytest.raises(ProviderThrottled) as raised:
            await llm.generate_structured("prompt", given.Output)

        assert raised.value.provider_message == given.PROVIDER_MESSAGE
        assert raised.value.waited_seconds == 30.0
        assert raised.value.usage == ProviderUsage(throttled_requests=3)
        assert isinstance(raised.value.__cause__, openai.RateLimitError)
        assert sleep.delays == [10.0, 20.0]

    async def test_a_hint_past_the_bound_raises_without_waiting(self):
        sleep = given.RecordingSleep()
        chat_model = FakeChatModel([given.a_throttle({"Retry-After": "400"}), given.an_answer()])
        llm = given.an_llm(chat_model, given.a_patience(sleep))

        with pytest.raises(ProviderThrottled):
            await llm.generate_structured("prompt", given.Output)

        assert sleep.delays == []

    async def test_the_parse_attempts_of_one_call_share_one_bound(self):
        sleep = given.RecordingSleep()
        chat_model = FakeChatModel(
            [
                given.a_throttle(),
                given.an_unreadable_answer(),
                given.an_unreadable_answer(),
                *given.throttled_forever(),
            ]
        )
        llm = given.an_llm(chat_model, given.a_patience(sleep, max_total_wait=15.0))

        with pytest.raises(ProviderThrottled) as raised:
            await llm.generate_structured("prompt", given.Output)

        assert sleep.delays == [10.0]
        assert raised.value.usage == ProviderUsage(
            input_tokens=200, output_tokens=100, throttled_requests=2, largest_input_tokens=100
        )

    async def test_a_refusal_after_a_throttled_retry_carries_the_429s(self):
        chat_model = FakeChatModel([given.a_throttle(), given.a_refusal()])
        llm = given.an_llm(chat_model, given.a_patience(given.RecordingSleep()))

        with pytest.raises(ProviderRefusal) as raised:
            await llm.generate_structured("prompt", given.Output)

        assert raised.value.usage.throttled_requests == 1

    async def test_a_429_marked_not_retryable_is_raised_as_is_without_waiting(self):
        sleep = given.RecordingSleep()
        chat_model = FakeChatModel([given.a_throttle({"x-should-retry": "false"})])
        llm = given.an_llm(chat_model, given.a_patience(sleep))

        with pytest.raises(openai.RateLimitError):
            await llm.generate_structured("prompt", given.Output)

        assert sleep.delays == []


class TestBreaker:
    async def test_after_an_exhausted_call_the_audit_sends_no_more_calls(self):
        sleep = given.RecordingSleep()
        patience = given.a_patience(sleep, max_total_wait=0.0)
        chat_model = FakeChatModel([given.a_throttle(), given.an_answer()])
        llm = given.an_llm(chat_model, patience)
        other_model = FakeChatModel([given.an_answer()])
        other_llm = given.an_llm(other_model, patience)

        with one_audit():
            with pytest.raises(ProviderThrottled):
                await llm.generate_structured("prompt", given.Output)
            with pytest.raises(ProviderThrottled) as same_llm:
                await llm.generate_structured("prompt", given.Output)
            with pytest.raises(ProviderThrottled) as other:
                await other_llm.generate_structured("prompt", given.Output)

        assert (chat_model.calls, other_model.calls) == (1, 0)
        assert sleep.delays == []
        assert given.PROVIDER_MESSAGE in same_llm.value.provider_message
        assert other.value.provider_message.startswith("not sent, an earlier call of this audit")

    async def test_a_call_waiting_when_the_breaker_trips_stops_at_its_next_retry(self):
        sleep = given.GatedSleep()
        waiting_model = FakeChatModel([given.a_throttle(), given.an_answer()])
        waiting_llm = given.an_llm(waiting_model, ThrottlePatience(sleep=sleep))
        exhausted_llm = given.an_llm(
            FakeChatModel(given.throttled_forever()), ThrottlePatience(max_total_wait=0.0)
        )

        async def exhaust_then_wake() -> None:
            try:
                await exhausted_llm.generate_structured("prompt", given.Output)
            finally:
                sleep.gate.set()

        with one_audit():
            outcomes = await asyncio.gather(
                waiting_llm.generate_structured("prompt", given.Output),
                exhaust_then_wake(),
                return_exceptions=True,
            )

        assert [type(outcome) for outcome in outcomes] == [ProviderThrottled, ProviderThrottled]
        assert waiting_model.calls == 1

    async def test_outside_any_audit_an_exhausted_call_does_not_block_the_next(self):
        patience = given.a_patience(given.RecordingSleep(), max_total_wait=0.0)
        llm = given.an_llm(FakeChatModel([given.a_throttle(), given.an_answer()]), patience)
        with pytest.raises(ProviderThrottled):
            await llm.generate_structured("prompt", given.Output)

        output, _ = await llm.generate_structured("prompt", given.Output)

        assert output == given.Output(value="ok")

    async def test_a_call_outside_any_audit_or_in_a_later_audit_is_sent(self):
        patience = given.a_patience(given.RecordingSleep(), max_total_wait=0.0)
        chat_model = FakeChatModel([given.a_throttle(), given.an_answer(), given.an_answer()])
        llm = given.an_llm(chat_model, patience)
        with one_audit(), pytest.raises(ProviderThrottled):
            await llm.generate_structured("prompt", given.Output)

        outside, _ = await llm.generate_structured("prompt", given.Output)
        with one_audit():
            later, _ = await llm.generate_structured("prompt", given.Output)

        assert outside == later == given.Output(value="ok")

    async def test_concurrent_audits_over_one_llm_each_have_their_own_breaker(self):
        patience = given.a_patience(given.RecordingSleep(), max_total_wait=0.0)
        llm = given.an_llm(FakeChatModel([given.a_throttle(), given.an_answer()]), patience)
        first_audit_done = asyncio.Event()

        async def exhausted_audit() -> None:
            with one_audit():
                try:
                    await llm.generate_structured("prompt", given.Output)
                finally:
                    first_audit_done.set()

        async def later_audit() -> given.Output:
            with one_audit():
                await first_audit_done.wait()
                output, _ = await llm.generate_structured("prompt", given.Output)
                return output

        outcomes = await asyncio.gather(exhausted_audit(), later_audit(), return_exceptions=True)

        assert isinstance(outcomes[0], ProviderThrottled)
        assert outcomes[1] == given.Output(value="ok")
