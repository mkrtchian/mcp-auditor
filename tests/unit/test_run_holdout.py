from pathlib import Path

import pytest

import tests.unit.support.test_holdout_census_given as given
from evals import run_holdout


def test_draw_order_exits_zero_and_prints_a_per_side_tally(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
):
    census = given.written(tmp_path, given.a_census())

    exit_code = run_holdout.main(["draw-order", "--census", str(census), "--cutoff", "2026-05-18"])

    assert exit_code == 0
    output = capsys.readouterr().out
    assert "pre_cutoff:" in output
    assert "post_cutoff:" in output


def test_draw_order_without_a_cutoff_is_an_argparse_error(tmp_path: Path):
    census = given.written(tmp_path, given.a_census())

    with pytest.raises(SystemExit) as exit_info:
        run_holdout.main(["draw-order", "--census", str(census)])

    assert exit_info.value.code == 2


def test_draw_order_on_a_malformed_census_exits_three(tmp_path: Path):
    malformed = tmp_path / "malformed.json"
    malformed.write_text("{not valid census}")

    exit_code = run_holdout.main(
        ["draw-order", "--census", str(malformed), "--cutoff", "2026-05-18"]
    )

    assert exit_code == 3
