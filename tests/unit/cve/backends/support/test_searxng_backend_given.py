from collections.abc import Sequence
from contextlib import AbstractContextManager

from evals.cve.backends.searxng import SearxngDocker, searxng_env
from evals.cve.detection.holdout_fixtures.cve_2026_58485_searxng import TARGET
from evals.cve.environments import Launch
from evals.cve.places import DETECTION_PLACES, kept_records, load_places
from evals.cve.planting_base import PlantingSpec
from tests.fakes.planting_docker import FakePlantingDocker


def the_targets_spec() -> PlantingSpec:
    return TARGET.planting_spec(kept_records(TARGET.kept_places, load_places(DETECTION_PLACES)))


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


def a_searxng_that_never_answers(planting: FakePlantingDocker) -> FakeSearxng:
    return FakeSearxng(planting, answers=False)


def a_launch(planting: FakePlantingDocker, searxng: FakeSearxng) -> AbstractContextManager[Launch]:
    return searxng_env("img", the_targets_spec(), docker=planting, searxng=searxng.docker())
