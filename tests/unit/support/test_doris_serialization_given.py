import threading
import time
from contextlib import AbstractContextManager
from dataclasses import dataclass, field

import pytest

from evals import cve_environments
from evals.cve_environments import Launch
from evals.cve_planting_base import PlantingHost, PlantingSpec, SentinelIntent, SymbolicUser

# Captured before any monkeypatch so the overlap window survives a faked `time.sleep`
# on the module under test.
_REAL_SLEEP = time.sleep


@dataclass
class OverlapRecorder:
    """A shared counter the faked helpers feed: `enter` on crossing into the critical region,
    `exit` on leaving it, holding a widening window open so a lock-less builder shows overlap."""

    window: float = 0.05
    _guard: threading.Lock = field(default_factory=threading.Lock)
    active: int = 0
    max_active: int = 0
    enter_threads: list[int] = field(default_factory=list[int])
    exit_threads: list[int] = field(default_factory=list[int])

    def enter(self) -> None:
        with self._guard:
            self.active += 1
            self.max_active = max(self.max_active, self.active)
            self.enter_threads.append(threading.get_ident())
        _REAL_SLEEP(self.window)

    def exit(self) -> None:
        with self._guard:
            self.active -= 1
            self.exit_threads.append(threading.get_ident())


def an_overlap_recorder() -> OverlapRecorder:
    return OverlapRecorder()


def doris_helpers_faked(monkeypatch: pytest.MonkeyPatch, recorder: OverlapRecorder) -> None:
    def reap(_name: str) -> None:
        recorder.exit()

    def start_sentinel(sentinel: SentinelIntent) -> str:
        return f"sentinel-{sentinel.host}"

    def no_sleep(_seconds: float) -> None:
        return None

    monkeypatch.setattr(cve_environments, "ensure_doris", recorder.enter)
    monkeypatch.setattr(cve_environments, "doris_rm", reap)
    monkeypatch.setattr(cve_environments, "start_doris_sentinel", start_sentinel)
    monkeypatch.setattr(cve_environments.time, "sleep", no_sleep)


def a_minimal_doris_spec() -> PlantingSpec:
    # `doris_db_env` reads only `spec.sentinels`; empty sentinels keep the faked builder minimal.
    return PlantingSpec(
        host=PlantingHost(
            user=SymbolicUser.UNPRIVILEGED, working_directory="/srv", has_network=True
        ),
        places=(),
        nonces={},
        files=(),
        env=(),
        account=None,
        hostname=None,
        sentinels=(),
        address_setups=(),
        host_entries=(),
        needs_network=False,
        needs_holder=False,
        unplaceable=0,
    )


@dataclass
class ThreadOutcome:
    thread_id: int = 0
    result: object = None
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
            entered.result = manager.__enter__()
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
