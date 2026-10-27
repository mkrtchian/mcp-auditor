"""The progress of one session's audits on a live bar, shared by the CVE and nuisance modes."""

from collections.abc import Awaitable, Callable

from rich.progress import Progress, TaskID


class AuditProgress:
    def __init__(self, progress: Progress) -> None:
        self._progress = progress
        self._preparing = progress.add_task("Preparing", total=None)
        self._auditing: TaskID | None = None
        self._unaudited = 0
        self._replaying: TaskID | None = None

    def announce(self, audits: int) -> None:
        self._progress.remove_task(self._preparing)
        if audits > 0:
            self._auditing = self._progress.add_task("Auditing", total=audits)
            self._unaudited = audits

    def tracked[T, R](self, audit: Callable[[T], Awaitable[R]]) -> Callable[[T], Awaitable[R]]:
        async def run(subject: T) -> R:
            result = await audit(subject)
            self._advance()
            return result

        return run

    def _advance(self) -> None:
        if self._auditing is None:
            return
        if self._unaudited > 0:
            self._unaudited -= 1
            self._progress.advance(self._auditing)
            return
        if self._replaying is None:
            self._replaying = self._progress.add_task("Replaying", total=None)
        self._progress.advance(self._replaying)
