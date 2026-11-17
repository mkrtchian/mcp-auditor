# One task owns every MCP session of a connection. The SDK's context managers hold anyio cancel
# scopes, which only the task that entered them may exit: a session closed from another task
# raises "Attempted to exit cancel scope in a different task". A relaunch is asked from a graph
# node, never from the task that opened the session, so the owner enters and exits every session
# it is asked for, from any task.
import asyncio
import sys
from collections.abc import Awaitable, Callable
from contextlib import AsyncExitStack, suppress
from dataclasses import dataclass, field
from enum import Enum

import anyio
from mcp import ClientSession

type SessionEntry = Callable[[AsyncExitStack], Awaitable[ClientSession]]


class SessionOwner:
    """Opens, replaces and closes the session on behalf of any task, and hands back the open
    session or the exception of the opening, which a failed opening raises in the shape the
    SDK's task groups give it. A session whose transport fails between two requests is lost:
    the owner unwinds it, so the error neither cancels the caller nor goes unseen. A close asked
    while a session opens cancels the opening rather than waiting it out."""

    def __init__(self, enter: SessionEntry, initialize_timeout: float) -> None:
        self._enter = enter
        self._initialize_timeout = initialize_timeout
        self._requests: asyncio.Queue[_Request] = asyncio.Queue()
        self._stack: AsyncExitStack | None = None
        self._task: asyncio.Task[None] | None = None
        self._opening = False

    @property
    def lost(self) -> bool:
        return self._stack is None

    async def open(self) -> ClientSession:
        self._task = asyncio.create_task(self._own())
        return await self._session_from(_RequestKind.OPEN)

    async def replace(self) -> ClientSession:
        return await self._session_from(_RequestKind.REPLACE)

    async def close(self) -> None:
        """Shielded, so a cancelled caller still leaves no server running."""
        if self._task is None:
            return
        with anyio.CancelScope(shield=True):
            try:
                if self._opening:
                    self._task.cancel()  # the owner's end closes whatever the opening left
                else:
                    await self._answer(_RequestKind.CLOSE)
            finally:
                await asyncio.wait({self._task})
                if not self._task.cancelled():
                    self._task.exception()  # read, so asyncio does not log it unseen

    async def _session_from(self, kind: "_RequestKind") -> ClientSession:
        session = await self._answer(kind)
        assert session is not None
        return session

    async def _answer(self, kind: "_RequestKind") -> ClientSession | None:
        assert self._task is not None
        request = _Request(kind)
        self._requests.put_nowait(request)
        # The owner's end is awaited too, so a cancelled owner leaves no caller waiting.
        try:
            await asyncio.wait({request.answer, self._task}, return_when=asyncio.FIRST_COMPLETED)
        except asyncio.CancelledError:
            request.answer.cancel()  # abandoned: the owner leaves it unanswered
            raise
        if not request.answer.done():
            raise ConnectionError("the MCP session's owner has ended")
        return request.answer.result()

    async def _own(self) -> None:
        try:
            while True:
                request = await self._next_request()
                try:
                    session = await self._carried_out(request)
                except Exception as error:
                    if not request.answer.done():  # cancelled by a caller that stopped waiting
                        request.answer.set_exception(error)
                else:
                    if not request.answer.done():
                        request.answer.set_result(session)
                if request.kind is _RequestKind.CLOSE:
                    return
        finally:
            # Only a cancelled owner gets here with a session open, and nobody awaits its close.
            with anyio.CancelScope(shield=True), suppress(Exception):
                await self._close_session()

    async def _next_request(self) -> "_Request":
        while True:
            try:
                return await self._requests.get()
            except asyncio.CancelledError as cancellation:
                # A task of the session's own group failed (a write to a dead server), and its
                # group cancels the task that entered it: this one, not the caller.
                if self._stack is None:
                    raise
                await self._unwind_lost_session(cancellation)

    async def _unwind_lost_session(self, cancellation: asyncio.CancelledError) -> None:
        stack, self._stack = self._stack, None
        assert stack is not None
        try:
            absorbed = await stack.__aexit__(
                type(cancellation), cancellation, cancellation.__traceback__
            )
        except Exception:
            return  # the transport's error, which the session's group raises once it has ended
        if not absorbed:
            raise cancellation  # not the session's cancellation: the owner itself is cancelled

    async def _carried_out(self, request: "_Request") -> ClientSession | None:
        if request.kind is not _RequestKind.OPEN:
            await self._close_session()
        if request.kind is _RequestKind.CLOSE or request.answer.cancelled():
            return None  # a replace its caller abandoned opens nothing
        self._opening = True
        try:
            return await self._open_session()
        finally:
            self._opening = False

    async def _open_session(self) -> ClientSession:
        stack = AsyncExitStack()
        try:
            session = await self._enter(stack)
            async with asyncio.timeout(self._initialize_timeout):
                await session.initialize()
        except BaseException as error:
            # Unwound with the exception, so the caller reads the group the SDK's task groups
            # raise from it, and no half-open session stays.
            if not await stack.__aexit__(*sys.exc_info()) or isinstance(
                error, asyncio.CancelledError
            ):
                raise
            raise ConnectionError("the MCP session ended while it opened") from None
        self._stack = stack
        return session

    async def _close_session(self) -> None:
        stack, self._stack = self._stack, None
        if stack is None:
            return
        try:
            await stack.aclose()
        except BaseExceptionGroup as group:
            # A server that logs its shutdown to stdout after the session stopped reading makes
            # the SDK's stdout reader raise BrokenResourceError (mcp 1.30.0): not a failure.
            if not _only_broken_streams(group):
                raise


class _RequestKind(Enum):
    OPEN = "open"
    REPLACE = "replace"
    CLOSE = "close"


@dataclass(frozen=True)
class _Request:
    kind: _RequestKind
    answer: asyncio.Future[ClientSession | None] = field(
        default_factory=lambda: asyncio.get_running_loop().create_future()
    )


def _only_broken_streams(group: BaseExceptionGroup) -> bool:
    _, rest = group.split(anyio.BrokenResourceError)
    return rest is None
