"""The sample table of the Doris cluster at a launch: seeded while empty, ready once it holds
rows, whatever an earlier audit of the command wrote to it. No Docker."""

import pytest

import tests.unit.cve.backends.support.test_doris_seed_given as given
from evals.cve.backends.doris import ensure_doris


def test_an_empty_sample_table_is_seeded_once(monkeypatch: pytest.MonkeyPatch):
    docker = given.a_cluster_whose_sample_table_holds(monkeypatch, rows=0)

    ensure_doris()

    assert docker.seedings == 1


@pytest.mark.parametrize("rows", [4, 5, 1])
def test_a_sample_table_holding_rows_is_ready_as_it_is(monkeypatch: pytest.MonkeyPatch, rows: int):
    docker = given.a_cluster_whose_sample_table_holds(monkeypatch, rows=rows)

    ensure_doris()

    assert docker.seedings == 0


def test_a_back_end_that_never_answers_fails_the_launch(monkeypatch: pytest.MonkeyPatch):
    given.a_cluster_whose_sample_table_holds(monkeypatch, rows=None)

    with pytest.raises(RuntimeError, match="did not become query-ready"):
        ensure_doris()
