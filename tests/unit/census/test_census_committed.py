from pathlib import Path

import pytest

from evals.cve.census.committed import committed_census
from evals.eval_session import Refused


def test_a_malformed_census_is_refused_as_malformed(tmp_path: Path):
    path = tmp_path / "census.json"
    path.write_text("{not valid census}")

    with pytest.raises(Refused) as refusal:
        committed_census(path)

    assert refusal.value.title == "Refused: the census is malformed."
