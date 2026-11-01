from pathlib import Path

import pytest

import tests.unit.support.test_nuisance_walk_record_given as given
from evals.census_classification import Criterion
from evals.nuisance_walk_record import load_walk_record, walk_record_problems


def test_an_empty_record_has_no_problem():
    nuisance_census = given.paired(given.a_census(), given.an_empty_record())

    assert walk_record_problems(nuisance_census) == []


def test_refuses_a_settlement_on_a_flaw_outside_the_draw_order():
    record = given.a_record_settling(("unpinnable", Criterion.PINNABLE, True))

    problems = walk_record_problems(given.paired(given.a_census(), record))

    assert len(problems) == 1
    assert "unpinnable" in problems[0]


def test_refuses_an_identity_on_a_flaw_outside_the_census():
    record = given.a_record_identifying("nowhere")

    problems = walk_record_problems(given.paired(given.a_census(), record))

    assert len(problems) == 1
    assert "nowhere" in problems[0]


def test_refuses_two_settlements_on_one_flaw_and_criterion():
    record = given.a_record_settling(
        ("queued", Criterion.PINNABLE, True), ("queued", Criterion.PINNABLE, True)
    )

    problems = walk_record_problems(given.paired(given.a_census(), record))

    assert len(problems) == 1
    assert "queued" in problems[0]


def test_accepts_two_settlements_on_one_flaw_for_different_criteria():
    record = given.a_record_settling(
        ("queued", Criterion.PINNABLE, True), ("queued", Criterion.GRAMMAR_CLASS, True)
    )

    assert walk_record_problems(given.paired(given.a_census(), record)) == []


def test_refuses_two_identities_on_one_flaw():
    record = given.a_record_identifying("queued", "queued")

    problems = walk_record_problems(given.paired(given.a_census(), record))

    assert len(problems) == 1
    assert "queued" in problems[0]


def test_refuses_a_settlement_contradicting_the_draw():
    census = given.a_census_settling("walked", Criterion.PINNABLE, True)
    record = given.a_record_settling(("walked", Criterion.PINNABLE, False))

    problems = walk_record_problems(given.paired(census, record))

    assert len(problems) == 1
    assert "walked" in problems[0]


def test_accepts_a_settlement_agreeing_with_the_draw():
    census = given.a_census_settling("walked", Criterion.PINNABLE, True)
    record = given.a_record_settling(("walked", Criterion.PINNABLE, True))

    assert walk_record_problems(given.paired(census, record)) == []


def test_a_census_without_a_draw_has_no_settlement_to_contradict():
    census = given.a_census().model_copy(update={"draw": None})
    record = given.a_record_settling(("queued", Criterion.PINNABLE, True))

    assert walk_record_problems(given.paired(census, record)) == []


def test_refuses_an_addition_of_size_zero():
    record = given.an_empty_record(size=0)

    problems = walk_record_problems(given.paired(given.a_census(), record))

    assert len(problems) == 1
    assert "size" in problems[0]


def test_load_raises_when_the_record_is_absent(tmp_path: Path):
    with pytest.raises(FileNotFoundError):
        load_walk_record(tmp_path / "absent.json", given.a_census())


def test_load_raises_with_the_problems_joined(tmp_path: Path):
    path = given.written(tmp_path, given.an_empty_record(size=0))

    with pytest.raises(ValueError, match="size"):
        load_walk_record(path, given.a_census())


def test_load_pairs_the_census_and_the_record(tmp_path: Path):
    census = given.a_census()
    record = given.a_record_settling(("queued", Criterion.PINNABLE, True))

    nuisance_census = load_walk_record(given.written(tmp_path, record), census)

    assert nuisance_census == given.paired(census, record)
