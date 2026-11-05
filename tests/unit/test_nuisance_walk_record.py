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


def test_refuses_a_queue_flaw_left_unsettled_on_a_classifier_disagreement():
    census = given.a_census_split_on_the_effect_of("queued")

    problems = walk_record_problems(given.paired(census, given.an_empty_record()))

    assert len(problems) == 1
    assert "queued" in problems[0]
    assert "effect_in_tool_response" in problems[0]


def test_accepts_a_queue_disagreement_once_settled():
    census = given.a_census_split_on_the_effect_of("queued")
    record = given.a_record_settling(("queued", Criterion.EFFECT_IN_TOOL_RESPONSE, False))

    assert walk_record_problems(given.paired(census, record)) == []


def test_leaves_a_queue_disagreement_on_the_grammar_class_to_the_admission():
    census = given.a_census_split_on_the_grammar_class_of("queued")

    assert walk_record_problems(given.paired(census, given.an_empty_record())) == []


def test_leaves_a_disagreement_on_a_holdout_walked_flaw_to_the_draw():
    census = given.a_census_split_on_the_effect_of("walked")

    assert walk_record_problems(given.paired(census, given.an_empty_record())) == []


def test_refuses_a_queue_flaw_whose_classifiers_name_two_packages_without_an_identity():
    census = given.a_census_naming_two_packages_for_the_queue()

    problems = walk_record_problems(given.paired(census, given.an_empty_record()))

    assert len(problems) == 1
    assert "queued" in problems[0]


def test_accepts_two_package_names_once_identified():
    census = given.a_census_naming_two_packages_for_the_queue()

    assert walk_record_problems(given.paired(census, given.a_record_identifying("queued"))) == []


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
