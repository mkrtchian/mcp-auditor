import pytest

from evals.cve.backends.doris import DORIS_SERVER_LAUNCH, doris_server_args
from evals.cve.detection import holdout_environments
from tests.fakes.planting_docker import FakePlantingDocker
from tests.unit.cve.backends.support.doris_launch import (
    OverlapRecorder,
    a_minimal_doris_spec,
    doris_helpers_faked,
    strip_pair,
)


# The nuisance launch mounts no layout (the nuisance suite has none); past it, the holdout launch
# must not drift from it.
def test_the_helper_and_the_holdout_env_differ_only_by_the_layout(
    monkeypatch: pytest.MonkeyPatch,
):
    doris_helpers_faked(monkeypatch, OverlapRecorder())
    spec = a_minimal_doris_spec()

    with holdout_environments.doris_db_env("image", spec, docker=FakePlantingDocker()) as launch:
        env_args = strip_pair(launch.args, "-v")
    helper = doris_server_args("server-name", "image", spec.host, DORIS_SERVER_LAUNCH)

    assert strip_pair(helper, "--name") == strip_pair(env_args, "--name")
