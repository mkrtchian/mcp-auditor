import argparse
import asyncio
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import AbstractContextManager, asynccontextmanager


def bounded[**P, R](call: Callable[P, Awaitable[R]], limit: int) -> Callable[P, Awaitable[R]]:
    """At most `limit` calls in flight at once, the others waiting their turn."""
    if limit < 1:
        raise ValueError(f"limit must be at least 1, got {limit}")
    semaphore = asyncio.Semaphore(limit)

    async def call_in_turn(*args: P.args, **kwargs: P.kwargs) -> R:
        async with semaphore:
            return await call(*args, **kwargs)

    return call_in_turn


@asynccontextmanager
async def entered_in_thread[T](manager: AbstractContextManager[T]) -> AsyncIterator[T]:
    """Enters and leaves a blocking context manager off the event loop."""
    value = await asyncio.to_thread(manager.__enter__)
    try:
        yield value
    except BaseException as exc:
        suppressed = await asyncio.to_thread(manager.__exit__, type(exc), exc, exc.__traceback__)
        if not suppressed:
            raise
    else:
        await asyncio.to_thread(manager.__exit__, None, None, None)


def positive_int(text: str) -> int:
    try:
        count = int(text)
    except ValueError:
        raise argparse.ArgumentTypeError(f"expected a whole number, got {text!r}") from None
    if count < 1:
        raise argparse.ArgumentTypeError(f"expected at least 1, got {count}")
    return count
