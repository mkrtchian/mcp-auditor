from contextlib import AbstractContextManager

import tests.unit.support.backend_launch_specs as specs
from evals.cve.backends.searxng import searxng_env
from evals.cve.detection.holdout_fixtures import cve_2026_58485_searxng
from evals.cve.environments import Launch
from tests.fakes.planting_docker import FakePlantingDocker
from tests.unit.support.fake_searxng import FakeSearxng


def a_launch(planting: FakePlantingDocker, searxng: FakeSearxng) -> AbstractContextManager[Launch]:
    spec = specs.a_spec_of_the_kept_places(cve_2026_58485_searxng.TARGET)
    return searxng_env("img", spec, docker=planting, searxng=searxng.docker())
