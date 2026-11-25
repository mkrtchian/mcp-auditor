import pytest

from evals.cve.backends.doris import DORIS_SERVER_LAUNCH, doris_cluster_run_args, doris_server_args
from evals.cve.detection import holdout_environments
from tests.fakes.planting_docker import FakePlantingDocker
from tests.unit.support.docker_argv import carries
from tests.unit.support.doris_launch import (
    OverlapRecorder,
    a_minimal_doris_spec,
    doris_helpers_faked,
    strip_pair,
)


# The nuisance launch mounts no layout (the nuisance suite has none); past it, the detection
# holdout launch must not drift from it.
def test_the_nuisance_and_the_detection_holdout_doris_launches_differ_only_by_the_layout(
    monkeypatch: pytest.MonkeyPatch,
):
    doris_helpers_faked(monkeypatch, OverlapRecorder())
    spec = a_minimal_doris_spec()

    with holdout_environments.doris_db_env("image", spec, docker=FakePlantingDocker()) as launch:
        detection_launch = strip_pair(launch.args, "-v")
    nuisance_launch = doris_server_args("server-name", "image", spec.host, DORIS_SERVER_LAUNCH)

    assert strip_pair(nuisance_launch, "--name") == strip_pair(detection_launch, "--name")


def test_the_doris_cluster_sets_the_backends_public_host_to_its_alias():
    assert carries(doris_cluster_run_args(), ["-e", "BE_CONFIG_EXTRA=public_host = doris"])


def test_the_doris_cluster_answers_on_its_alias():
    assert carries(doris_cluster_run_args(), ["--network-alias", "doris"])


def test_the_doris_cluster_is_named_after_its_alias():
    assert carries(doris_cluster_run_args(), ["--hostname", "doris"])
