"""How the audits of a holdout or nuisance run stop together. A first exception out of a target's
runs cancels every target still in flight, and the run keeps what had finished, so a fatal
provider error spends no more calls than were already sent."""

import asyncio
from collections.abc import Awaitable, Callable, Sequence


async def first_failure[T, R](
    items: Sequence[T], run: Callable[[T], Awaitable[R]]
) -> tuple[list[tuple[T, R]], BaseException | None]:
    """The items whose run finished, with its outcome, and the first exception a run raised."""
    tasks = [asyncio.create_task(_awaited(lambda item=item: run(item))) for item in items]
    if not tasks:
        return [], None
    try:
        done, _ = await asyncio.wait(tasks, return_when=asyncio.FIRST_EXCEPTION)
    finally:
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
    ended = [(item, task) for item, task in zip(items, tasks, strict=True) if task in done]
    failures = [task.exception() for _, task in ended if task.exception() is not None]
    finished = [(item, task.result()) for item, task in ended if task.exception() is None]
    return finished, failures[0] if failures else None


async def sibling_runs[R](runs: int, run: Callable[[], Awaitable[R]]) -> list[R]:
    """The outcomes of `runs` runs in order. One run's exception cancels its siblings and is
    raised bare, out of the task group's exception group."""
    try:
        async with asyncio.TaskGroup() as group:
            tasks = [group.create_task(_awaited(run)) for _ in range(runs)]
    except ExceptionGroup as failed:
        # A `from` would overwrite the leaf's own cause, the provider error of a ProviderFatal.
        raise failed.exceptions[0]  # noqa: B904
    return [task.result() for task in tasks]


async def _awaited[R](call: Callable[[], Awaitable[R]]) -> R:
    return await call()
