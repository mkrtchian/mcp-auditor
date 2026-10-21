import os
import pathlib

import pytest

from tests.integration.support.cve_stub_target import a_docker_that_runs_its_command_on_the_host


@pytest.fixture
def docker_on_the_host(monkeypatch: pytest.MonkeyPatch, tmp_path: pathlib.Path) -> None:
    docker_dir = a_docker_that_runs_its_command_on_the_host(tmp_path)
    monkeypatch.setenv("PATH", f"{docker_dir}{os.pathsep}{os.environ['PATH']}")
