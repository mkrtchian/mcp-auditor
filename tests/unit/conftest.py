import os
import stat

import pytest

_DOCKER_SHIM = """#!/bin/sh
echo "a unit test reached docker: $PYTEST_CURRENT_TEST" >&2
exit 99
"""


@pytest.fixture(autouse=True)
def _no_docker_in_unit_tests(
    monkeypatch: pytest.MonkeyPatch, tmp_path_factory: pytest.TempPathFactory
) -> None:
    shim_directory = tmp_path_factory.mktemp("docker_shim")
    shim = shim_directory / "docker"
    shim.write_text(_DOCKER_SHIM)
    shim.chmod(shim.stat().st_mode | stat.S_IXUSR)
    monkeypatch.setenv("PATH", f"{shim_directory}{os.pathsep}{os.environ['PATH']}")
