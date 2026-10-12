import subprocess

from tests.integration.support.test_cve_planting_given import RecordingPlanting


def nothing_it_made_outlives(docker: RecordingPlanting) -> None:
    assert docker.networks and docker.containers
    assert not [name for name in docker.containers if _exists("container", name)]
    assert not [name for name in docker.networks if _exists("network", name)]


def _exists(kind: str, name: str) -> bool:
    result = subprocess.run(["docker", kind, "inspect", name], capture_output=True, text=True)
    return result.returncode == 0
