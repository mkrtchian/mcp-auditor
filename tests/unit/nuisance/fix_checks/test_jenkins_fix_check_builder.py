from evals.cve.backends.jenkins import JENKINS_BRIDGE, JENKINS_PORT
from evals.cve.nuisance.fix_checks import cve_2026_10276_jenkins as jenkins
from tests.unit.support.docker_argv import value_after

_ADDRESS = "198.18.2.123"


def test_the_per_launch_controller_runs_on_the_jenkins_bridge():
    args = jenkins.controller_args("c", _ADDRESS)

    assert value_after(args, "--network") == JENKINS_BRIDGE
    assert value_after(args, "--ip") == _ADDRESS


def test_the_fix_check_server_points_jenkins_url_at_the_per_launch_controller_on_8080():
    args = jenkins.server_args("image", _ADDRESS)

    assert f"JENKINS_URL=http://{_ADDRESS}:{JENKINS_PORT}" in args
