from evals.cve.backends.jenkins import JENKINS_BRIDGE, JENKINS_PORT
from evals.cve.nuisance.fix_checks import cve_2026_10276_jenkins as jenkins
from evals.cve.planting_base import confinement_args, memory_bound_args
from tests.unit.support.docker_argv import carries

_ADDRESS = "198.18.2.123"


def test_the_per_launch_controller_runs_on_the_jenkins_bridge():
    args = jenkins.controller_args("c", _ADDRESS)

    assert args[args.index("--network") + 1] == JENKINS_BRIDGE
    assert args[args.index("--ip") + 1] == _ADDRESS


def test_the_per_launch_controller_runs_under_the_confinement_of_the_cve_benchmark():
    args = jenkins.controller_args("c", _ADDRESS)

    for option in confinement_args():
        assert option in args
    assert carries(args, memory_bound_args())
    assert "--cap-add" not in args


def test_the_fix_check_server_points_jenkins_url_at_the_per_launch_controller_on_8080():
    args = jenkins.server_args("image", _ADDRESS)

    assert f"JENKINS_URL=http://{_ADDRESS}:{JENKINS_PORT}" in args
