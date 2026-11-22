from contextlib import AbstractContextManager

from evals.cve.backends.searxng import searxng_env
from evals.cve.environments import Launch
from tests.fakes.planting_docker import FakePlantingDocker
from tests.unit.cve.backends.support.fake_searxng import FakeSearxng, the_targets_spec


def a_searxng_that_never_answers(planting: FakePlantingDocker) -> FakeSearxng:
    return FakeSearxng(planting, answers=False)


def a_launch(planting: FakePlantingDocker, searxng: FakeSearxng) -> AbstractContextManager[Launch]:
    return searxng_env("img", the_targets_spec(), docker=planting, searxng=searxng.docker())
