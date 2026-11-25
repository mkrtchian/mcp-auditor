from collections.abc import Sequence

from evals.cve.backends.searxng import SearxngDocker
from tests.fakes.planting_docker import FakePlantingDocker


class FakeSearxng:
    """Starts SearXNG and finds it ready at once, unless told it never answers, and records what
    it starts, waits on and removes, with the holders still standing at each removal."""

    def __init__(self, planting: FakePlantingDocker, *, answers: bool = True) -> None:
        self.planting = planting
        self.answers = answers
        self.started: list[list[str]] = []
        self.awaited: list[str] = []
        self.removed: list[str] = []
        self.holders_at_removal: list[list[str]] = []

    def start(self, run_args: Sequence[str]) -> None:
        self.started.append(list(run_args))

    def wait_ready(self, name: str) -> None:
        self.awaited.append(name)
        if not self.answers:
            raise RuntimeError(f"{name} never answered")

    def remove(self, name: str) -> None:
        self.removed.append(name)
        self.holders_at_removal.append(list(self.planting.holders))

    def docker(self) -> SearxngDocker:
        return SearxngDocker(self.start, self.wait_ready, self.remove)
