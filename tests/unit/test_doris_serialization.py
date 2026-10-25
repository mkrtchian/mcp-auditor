import asyncio

import pytest

import tests.unit.support.test_doris_serialization_given as given
from evals import cve_environments
from evals.concurrency import entered_in_thread


async def test_concurrent_doris_launches_never_overlap_in_the_critical_region(
    monkeypatch: pytest.MonkeyPatch,
):
    recorder = given.an_overlap_recorder()
    given.doris_helpers_faked(monkeypatch, recorder)
    spec = given.a_minimal_doris_spec()

    async def enter_once() -> None:
        async with entered_in_thread(cve_environments.doris_db_env("image", spec)):
            await asyncio.sleep(0.01)

    await asyncio.gather(enter_once(), enter_once(), enter_once())

    assert recorder.max_active == 1


def test_a_cross_thread_enter_and_exit_complete_without_raising(monkeypatch: pytest.MonkeyPatch):
    recorder = given.an_overlap_recorder()
    given.doris_helpers_faked(monkeypatch, recorder)
    spec = given.a_minimal_doris_spec()
    manager = cve_environments.doris_db_env("image", spec)

    crossing = given.enter_then_exit_on_separate_threads(manager)

    assert crossing.entered.error is None
    assert crossing.left.error is None
    assert crossing.entered.thread_id != crossing.left.thread_id
