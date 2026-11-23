"""The launch retry of the checks that launch a server before a run: the calibration check, the
layout check and the nuisance vet."""

from collections.abc import Awaitable, Callable

# A launch or handshake that fails is retried up to this many launches of the version: one
# observation of a version may take that many launches. A launch that ran is never retried.
PRE_RUN_LAUNCH_ATTEMPTS = 3


class NotLaunched(Exception):
    """A launch or handshake that failed: the one failure the pre-run check retries."""


async def first_launch[T](attempt: Callable[[], Awaitable[T]]) -> T | None:
    """What the first launch that ran observed, in up to `PRE_RUN_LAUNCH_ATTEMPTS` launches, or
    None when none of them launched."""
    for _ in range(PRE_RUN_LAUNCH_ATTEMPTS):
        try:
            return await attempt()
        except NotLaunched:
            continue
    return None
