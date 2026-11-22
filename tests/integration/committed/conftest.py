import pytest

from tests.unit.support.docker_shim import install_docker_shim


@pytest.fixture(autouse=True)
def _no_docker_in_committed_content_tests(
    monkeypatch: pytest.MonkeyPatch, tmp_path_factory: pytest.TempPathFactory
) -> None:
    install_docker_shim(monkeypatch, tmp_path_factory)
