import threading
from contextlib import AbstractContextManager
from dataclasses import dataclass

from evals.cve.environments import Launch


@dataclass
class ThreadOutcome:
    thread_id: int = 0
    error: BaseException | None = None


@dataclass
class CrossThreadRun:
    entered: ThreadOutcome
    left: ThreadOutcome


def enter_then_exit_on_separate_threads(manager: AbstractContextManager[Launch]) -> CrossThreadRun:
    # The entering thread stays alive through the exit so the two have genuinely distinct,
    # non-recycled identifiers: the lock is acquired here and released on the other thread,
    # the cross-thread release a plain `Lock` permits and an `RLock` would reject.
    entered, left = ThreadOutcome(), ThreadOutcome()
    enter_done, exit_done = threading.Event(), threading.Event()

    def enter_target() -> None:
        entered.thread_id = threading.get_ident()
        try:
            manager.__enter__()
        except Exception as exc:
            entered.error = exc
        enter_done.set()
        exit_done.wait()

    def exit_target() -> None:
        left.thread_id = threading.get_ident()
        try:
            manager.__exit__(None, None, None)
        except Exception as exc:
            left.error = exc

    entering = threading.Thread(target=enter_target)
    entering.start()
    enter_done.wait()
    leaving = threading.Thread(target=exit_target)
    leaving.start()
    leaving.join()
    exit_done.set()
    entering.join()
    return CrossThreadRun(entered=entered, left=left)
