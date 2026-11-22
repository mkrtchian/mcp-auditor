import pytest

from evals.cve.nuisance.backend_registry import BACKENDS


@pytest.mark.parametrize("key", sorted(BACKENDS))
def test_every_served_path_of_a_registered_backend_exists(key: str):
    missing = [path for path in BACKENDS[key].served if not path.is_file()]

    assert missing == []
