from pathlib import Path

import pytest

import tests.unit.support.test_census_draw_given as draw_given
import tests.unit.support.test_holdout_census_given as given
from evals import run_nuisance


def test_walk_prints_the_population_and_exits_zero(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
):
    census = draw_given.a_census_with_draw(draw_given.a_draw())
    path = given.written(tmp_path, census)

    exit_code = run_nuisance.main(["walk", "--census", str(path)])

    out = capsys.readouterr().out
    assert exit_code == 0
    assert "servers reached by the walk" in out
    assert "npm:@acme/files" in out
    assert "reached by CVE-2025-0001" in out
    assert "CVE-2025-0001" in out


def test_a_malformed_census_exits_three(tmp_path: Path):
    path = tmp_path / "holdout_census.json"
    path.write_text("{ not valid json")

    assert run_nuisance.main(["walk", "--census", str(path)]) == 3
