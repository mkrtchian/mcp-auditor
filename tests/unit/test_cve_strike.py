import tests.unit.support.test_cve_grammar_given as grammar
import tests.unit.support.test_cve_strike_given as given
from evals.cve_grammar import CreditCheck, CVEStatus, grade_run
from evals.cve_proofs import GradedRun, UnitPlace, struck_by_replay
from evals.cve_report_units import units_of

AIMED = {"path": grammar.AIMED_PATH}


def test_a_nonce_under_fail_is_detected():
    report = grammar.a_report(cases=[grammar.a_case(response=f"leaked {given.NONCE_A}")])

    grade = grade_run(given.a_target({given.PLACE_A: given.NONCE_A}), units_of(report))

    assert grade.status == CVEStatus.DETECTED


def test_the_same_unit_place_struck_regrades_to_the_next_rung():
    report = grammar.a_report(
        cases=[
            grammar.a_case(response=f"leaked {given.NONCE_A}", verdict=grammar.FAIL),
            grammar.a_case(response=f"leaked {given.NONCE_A}", verdict=grammar.PASS),
        ]
    )
    target = given.a_target({given.PLACE_A: given.NONCE_A})
    units = units_of(report)

    detected = grade_run(target, units)
    struck = grade_run(target, units, CreditCheck(frozenset({UnitPlace(0, given.PLACE_A)}), False))

    assert detected.status == CVEStatus.DETECTED
    assert struck.status == CVEStatus.REACHED_BUT_JUDGED_PASS


def test_a_pair_struck_in_one_unit_leaves_the_same_place_credit_in_another_unit():
    report = grammar.a_report(
        cases=[
            grammar.a_case(response=f"leaked {given.NONCE_A}"),
            grammar.a_case(response=f"leaked {given.NONCE_A}"),
        ]
    )
    target = given.a_target({given.PLACE_A: given.NONCE_A})

    grade = grade_run(
        target, units_of(report), CreditCheck(frozenset({UnitPlace(0, given.PLACE_A)}), False)
    )

    assert grade.status == CVEStatus.DETECTED


def test_a_nonce_from_a_different_location_is_not_struck():
    report = grammar.a_report(cases=[grammar.a_case(response=f"leaked {given.NONCE_A}")])
    target = given.a_target({given.PLACE_A: given.NONCE_A, given.PLACE_B: given.NONCE_B})

    grade = grade_run(
        target, units_of(report), CreditCheck(frozenset({UnitPlace(0, given.PLACE_B)}), False)
    )

    assert grade.status == CVEStatus.DETECTED


def test_an_echoed_nonce_never_counts():
    case = grammar.a_case(response=f"echo {given.NONCE_A}", arguments={"path": given.NONCE_A})
    target = given.a_target({given.PLACE_A: given.NONCE_A})

    grade = grade_run(target, units_of(grammar.a_report(cases=[case])))

    assert grade.status == CVEStatus.MISSED


def test_a_run_with_two_locations_keeps_detection_when_only_one_is_struck():
    case = grammar.a_case(response=f"leaked {given.NONCE_A} and {given.NONCE_B}")
    target = given.a_target({given.PLACE_A: given.NONCE_A, given.PLACE_B: given.NONCE_B})

    grade = grade_run(
        target,
        units_of(grammar.a_report(cases=[case])),
        CreditCheck(frozenset({UnitPlace(0, given.PLACE_A)}), False),
    )

    assert grade.status == CVEStatus.DETECTED


def test_an_unchecked_check_keeps_the_status_and_records_the_missed_status():
    case = grammar.a_case(response=f"leaked {given.NONCE_A}")
    target = given.a_target({given.PLACE_A: given.NONCE_A})

    grade = grade_run(
        target, units_of(grammar.a_report(cases=[case])), CreditCheck(frozenset(), unchecked=True)
    )

    assert grade.status == CVEStatus.DETECTED
    assert grade.status_if_unchecked_missed == CVEStatus.MISSED
    assert grade.unchecked_places == frozenset({given.PLACE_A})


def test_a_target_with_no_class_counts_every_category_in_fail_without_proof():
    case = grammar.a_case(response="denied", arguments=AIMED, category=grammar.RESOURCE_ABUSE)
    target = given.a_target({given.PLACE_A: given.NONCE_A}, mechanism=None)

    grade = grade_run(target, units_of(grammar.a_report(cases=[case])))

    assert grade.fail_without_proof


def test_a_place_proven_in_the_same_unit_on_both_sides_is_struck():
    run = GradedRun(
        given.a_target({given.PLACE_A: given.NONCE_A}), [given.leaking_unit(given.NONCE_A)]
    )
    replay = GradedRun(
        given.a_target({given.PLACE_A: given.FRESH_A}), [given.leaking_unit(given.FRESH_A)]
    )

    assert struck_by_replay(run, replay) == frozenset({UnitPlace(0, given.PLACE_A)})


def test_a_place_proven_on_the_replay_in_another_unit_only_is_not_struck():
    run = GradedRun(
        given.a_target({given.PLACE_A: given.NONCE_A}),
        [given.leaking_unit(given.NONCE_A), given.leaking_unit()],
    )
    replay = GradedRun(
        given.a_target({given.PLACE_A: given.FRESH_A}),
        [given.leaking_unit(), given.leaking_unit(given.FRESH_A)],
    )

    assert struck_by_replay(run, replay) == frozenset()


def test_a_fresh_nonce_of_another_place_strikes_nothing():
    run = GradedRun(
        given.a_target({given.PLACE_A: given.NONCE_A}), [given.leaking_unit(given.NONCE_A)]
    )
    replay = GradedRun(
        given.a_target({given.PLACE_A: given.FRESH_A, given.PLACE_B: given.FRESH_B}),
        [given.leaking_unit(given.FRESH_B)],
    )

    assert struck_by_replay(run, replay) == frozenset()


def test_a_replayed_output_that_only_echoes_an_argument_strikes_nothing():
    run = GradedRun(
        given.a_target({given.PLACE_A: given.NONCE_A}), [given.leaking_unit(given.NONCE_A)]
    )
    replay = GradedRun(
        given.a_target({given.PLACE_A: given.FRESH_A}), [given.echoing_unit(given.FRESH_A)]
    )

    assert struck_by_replay(run, replay) == frozenset()
