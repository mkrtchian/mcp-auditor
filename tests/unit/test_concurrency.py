import argparse
import asyncio

import pytest

import tests.unit.support.test_concurrency_given as given
from evals.concurrency import bounded, entered_in_thread, positive_int


async def test_no_more_calls_than_the_limit_are_in_flight():
    probe = given.InFlightProbe()
    call = bounded(probe.call, 3)

    await asyncio.gather(*(call(index) for index in range(10)))

    assert probe.highest == 3


async def test_results_come_back_in_submission_order():
    call = bounded(given.InFlightProbe().call, 3)

    results = await asyncio.gather(*(call(index) for index in range(10)))

    assert results == list(range(10))


def test_a_limit_below_one_is_refused():
    with pytest.raises(ValueError):
        bounded(given.InFlightProbe().call, 0)


async def test_the_manager_is_entered_its_value_yielded_and_left():
    manager = given.RecordingManager()

    async with entered_in_thread(manager) as value:
        assert value == "entered value"
        assert manager.events == ["enter"]

    assert manager.events == ["enter", "exit"]


async def test_a_failing_body_still_leaves_the_manager_and_its_error_propagates():
    manager = given.RecordingManager()
    error = RuntimeError("body failed")

    with pytest.raises(RuntimeError) as raised:
        async with entered_in_thread(manager):
            raise error

    assert raised.value is error
    assert manager.events == ["enter", "exit"]
    assert manager.exit_exception is error


async def test_a_blocking_enter_leaves_the_event_loop_free():
    manager = given.RecordingManager(enter_delay=0.2)
    ticker = given.Ticker()
    ticking = asyncio.create_task(ticker.run())

    async with entered_in_thread(manager):
        ticks_during_enter = ticker.ticks
    ticking.cancel()

    assert ticks_during_enter > 0


def test_a_count_below_one_is_refused_as_an_argument():
    with pytest.raises(argparse.ArgumentTypeError):
        positive_int("0")


def test_a_non_integer_is_refused_as_an_argument():
    with pytest.raises(argparse.ArgumentTypeError):
        positive_int("many")


def test_a_positive_count_is_accepted_as_an_argument():
    assert positive_int("3") == 3
