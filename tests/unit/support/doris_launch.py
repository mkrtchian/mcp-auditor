"""The detection holdout Doris launch on fakes: its helpers patched out and a spec that plants
nothing."""

import threading
import time
from dataclasses import dataclass, field
from types import SimpleNamespace

import pytest

from evals.cve.detection import holdout_environments
from evals.cve.planting import RANDOM_NONCES, planting_spec
from evals.cve.planting_base import PlantingHost, PlantingSpec, SentinelIntent, SymbolicUser


@dataclass
class OverlapRecorder:
    """A shared counter the faked helpers feed: `enter` on crossing into the critical region,
    `exit` on leaving it, holding a widening window open so a lock-less builder shows overlap."""

    window: float = 0.05
    _guard: threading.Lock = field(default_factory=threading.Lock)
    active: int = 0
    max_active: int = 0

    def enter(self) -> None:
        with self._guard:
            self.active += 1
            self.max_active = max(self.max_active, self.active)
        time.sleep(self.window)

    def exit(self) -> None:
        with self._guard:
            self.active -= 1


def doris_helpers_faked(monkeypatch: pytest.MonkeyPatch, recorder: OverlapRecorder) -> None:
    def reap(_name: str) -> None:
        recorder.exit()

    def start_sentinel(sentinel: SentinelIntent) -> str:
        return f"sentinel-{sentinel.host}"

    def no_sleep(_seconds: float) -> None:
        return None

    monkeypatch.setattr(holdout_environments, "ensure_doris", recorder.enter)
    monkeypatch.setattr(holdout_environments, "doris_rm", reap)
    monkeypatch.setattr(holdout_environments, "start_doris_sentinel", start_sentinel)
    monkeypatch.setattr(holdout_environments, "time", SimpleNamespace(sleep=no_sleep))


def a_minimal_doris_spec() -> PlantingSpec:
    return planting_spec(
        (), PlantingHost(SymbolicUser.UNPRIVILEGED, "/srv/app", has_network=True), RANDOM_NONCES
    )


def strip_pair(args: list[str], flag: str) -> list[str]:
    i = args.index(flag)
    return args[:i] + args[i + 2 :]
