from contextlib import AbstractContextManager

import tests.unit.support.backend_launch_specs as specs
from evals.cve.backends.ckan_holdout import ckan_ssrf_env
from evals.cve.detection.holdout_fixtures import cve_2026_33060_ckan
from evals.cve.environments import Launch
from tests.fakes.planting_docker import FakePlantingDocker
from tests.unit.support.fake_ckan import FakeCkanDocker


def a_launch() -> AbstractContextManager[Launch]:
    spec = specs.a_spec_of_the_kept_places(cve_2026_33060_ckan.TARGET)
    return ckan_ssrf_env("img", spec, docker=FakePlantingDocker(), ckan=FakeCkanDocker().docker())
