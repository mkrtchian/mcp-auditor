import tests.unit.cve.support.strike_inputs as strike
import tests.unit.support.grammar_inputs as grammar
from evals.cve.grammar import CreditCheck, TargetStatus, grade_run
from evals.cve.proofs import GradedRun, UnitPlace, struck_by_replay
from evals.cve.report_units import units_of


def test_the_same_unit_place_struck_regrades_to_the_next_rung():
    report = grammar.a_report(
        cases=[
            grammar.a_case(response=f"leaked {strike.NONCE_A}", verdict=grammar.FAIL),
            grammar.a_case(response=f"leaked {strike.NONCE_A}", verdict=grammar.PASS),
        ]
    )
    target = strike.a_target({strike.PLACE_A: strike.NONCE_A})
    units = units_of(report)

    detected = grade_run(target, units)
    struck = grade_run(target, units, CreditCheck(frozenset({UnitPlace(0, strike.PLACE_A)}), False))

    assert detected.status == TargetStatus.DETECTED
    assert struck.status == TargetStatus.REACHED_BUT_JUDGED_PASS


def test_a_pair_struck_in_one_unit_leaves_the_same_place_credit_in_another_unit():
    report = grammar.a_report(
        cases=[
            grammar.a_case(response=f"leaked {strike.NONCE_A}"),
            grammar.a_case(response=f"leaked {strike.NONCE_A}"),
        ]
    )
    target = strike.a_target({strike.PLACE_A: strike.NONCE_A})

    grade = grade_run(
        target, units_of(report), CreditCheck(frozenset({UnitPlace(0, strike.PLACE_A)}), False)
    )

    assert grade.status == TargetStatus.DETECTED


def test_a_nonce_from_a_different_location_is_not_struck():
    report = grammar.a_report(cases=[grammar.a_case(response=f"leaked {strike.NONCE_A}")])
    target = strike.a_target({strike.PLACE_A: strike.NONCE_A, strike.PLACE_B: strike.NONCE_B})

    grade = grade_run(
        target, units_of(report), CreditCheck(frozenset({UnitPlace(0, strike.PLACE_B)}), False)
    )

    assert grade.status == TargetStatus.DETECTED


def test_a_run_with_two_locations_keeps_detection_when_only_one_is_struck():
    case = grammar.a_case(response=f"leaked {strike.NONCE_A} and {strike.NONCE_B}")
    target = strike.a_target({strike.PLACE_A: strike.NONCE_A, strike.PLACE_B: strike.NONCE_B})

    grade = grade_run(
        target,
        units_of(grammar.a_report(cases=[case])),
        CreditCheck(frozenset({UnitPlace(0, strike.PLACE_A)}), False),
    )

    assert grade.status == TargetStatus.DETECTED


def test_an_unchecked_check_keeps_the_status_and_records_the_missed_status():
    case = grammar.a_case(response=f"leaked {strike.NONCE_A}")
    target = strike.a_target({strike.PLACE_A: strike.NONCE_A})

    grade = grade_run(
        target, units_of(grammar.a_report(cases=[case])), CreditCheck(frozenset(), unchecked=True)
    )

    assert grade.status == TargetStatus.DETECTED
    assert grade.status_if_unchecked_missed == TargetStatus.MISSED
    assert grade.unchecked_places == frozenset({strike.PLACE_A})


def test_a_nonce_in_an_unjudged_unit_is_neither_surfaced_nor_unchecked():
    case = grammar.a_case(response=f"leaked {strike.NONCE_A}", verdict=None)
    target = strike.a_target({strike.PLACE_A: strike.NONCE_A})

    grade = grade_run(
        target, units_of(grammar.a_report(cases=[case])), CreditCheck(frozenset(), unchecked=True)
    )

    assert grade.surfaced_places == frozenset()
    assert grade.unchecked_places == frozenset()


def test_a_nonce_in_a_pass_judged_unit_is_still_reported_unchecked():
    case = grammar.a_case(response=f"leaked {strike.NONCE_A}", verdict=grammar.PASS)
    target = strike.a_target({strike.PLACE_A: strike.NONCE_A})

    grade = grade_run(
        target, units_of(grammar.a_report(cases=[case])), CreditCheck(frozenset(), unchecked=True)
    )

    assert grade.unchecked_places == frozenset({strike.PLACE_A})


def test_a_place_proven_in_the_same_unit_on_both_sides_is_struck():
    run = GradedRun(
        strike.a_target({strike.PLACE_A: strike.NONCE_A}), [strike.leaking_unit(strike.NONCE_A)]
    )
    replay = GradedRun(
        strike.a_target({strike.PLACE_A: strike.FRESH_A}), [strike.leaking_unit(strike.FRESH_A)]
    )

    assert struck_by_replay(run, replay) == frozenset({UnitPlace(0, strike.PLACE_A)})


def test_a_place_proven_on_the_replay_in_another_unit_only_is_not_struck():
    run = GradedRun(
        strike.a_target({strike.PLACE_A: strike.NONCE_A}),
        [strike.leaking_unit(strike.NONCE_A), strike.leaking_unit()],
    )
    replay = GradedRun(
        strike.a_target({strike.PLACE_A: strike.FRESH_A}),
        [strike.leaking_unit(), strike.leaking_unit(strike.FRESH_A)],
    )

    assert struck_by_replay(run, replay) == frozenset()


def test_a_fresh_nonce_of_another_place_strikes_nothing():
    run = GradedRun(
        strike.a_target({strike.PLACE_A: strike.NONCE_A}), [strike.leaking_unit(strike.NONCE_A)]
    )
    replay = GradedRun(
        strike.a_target({strike.PLACE_A: strike.FRESH_A, strike.PLACE_B: strike.FRESH_B}),
        [strike.leaking_unit(strike.FRESH_B)],
    )

    assert struck_by_replay(run, replay) == frozenset()


def test_a_replayed_output_that_only_echoes_an_argument_strikes_nothing():
    run = GradedRun(
        strike.a_target({strike.PLACE_A: strike.NONCE_A}), [strike.leaking_unit(strike.NONCE_A)]
    )
    replay = GradedRun(
        strike.a_target({strike.PLACE_A: strike.FRESH_A}), [strike.echoing_unit(strike.FRESH_A)]
    )

    assert struck_by_replay(run, replay) == frozenset()
