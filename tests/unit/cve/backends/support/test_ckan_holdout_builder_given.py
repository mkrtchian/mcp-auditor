from contextlib import AbstractContextManager

from evals.cve.backends.ckan_holdout import ckan_ssrf_env
from evals.cve.environments import Launch
from tests.fakes.planting_docker import FakePlantingDocker
from tests.unit.cve.backends.support.fake_ckan import FakeCkanDocker, the_targets_spec


def a_launch() -> AbstractContextManager[Launch]:
    return ckan_ssrf_env(
        "img", the_targets_spec(), docker=FakePlantingDocker(), ckan=FakeCkanDocker().docker()
    )
