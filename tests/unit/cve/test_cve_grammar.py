from typing import Any

import pytest

import tests.unit.support.grammar_inputs as grammar
from evals.cve.grammar import FlawClass, MissKind, TargetStatus, grade_run, resolve
from evals.cve.proofs import is_aimed, proofs_in
from evals.cve.report_units import units_of
from evals.cve.units import unit_of_exchanges
from mcp_auditor.domain.models import AuditCategory, TestCase

NONCE = grammar.NONCE
PLACE = grammar.PLACE
AIMED = {"path": grammar.AIMED_PATH}
COMMAND_EXECUTION = FlawClass.COMMAND_EXECUTION
READ_OUTSIDE_SCOPE = FlawClass.READ_OUTSIDE_SCOPE
INTERNAL_FETCH = FlawClass.INTERNAL_FETCH


@pytest.mark.parametrize(
    "case",
    [
        grammar.a_case(response=f"leaked {NONCE}"),
        grammar.a_case(error=f"boom {NONCE}"),
        grammar.a_case(response={"content": NONCE}),
    ],
    ids=["response", "error", "dict_response"],
)
def test_nonce_in_a_fail_case_output_is_detected(case: TestCase):
    grade = grade_run(grammar.a_read_target(), units_of(grammar.a_report(cases=[case])))

    assert grade.status == TargetStatus.DETECTED
    assert grade.evidence is not None and NONCE in grade.evidence
    assert grade.category == grammar.INFO_LEAKAGE


def test_nonce_echoed_from_the_case_arguments_is_not_a_proof():
    case = grammar.a_case(response=f"no file {NONCE}", arguments={"path": NONCE})

    grade = grade_run(grammar.a_read_target(), units_of(grammar.a_report(cases=[case])))

    assert grade.status == TargetStatus.MISSED


def test_nonce_carried_by_an_earlier_chain_step_is_not_a_proof():
    chain = grammar.a_chain(
        [
            grammar.a_step(arguments={"path": NONCE}),
            grammar.a_step(response=f"echo {NONCE}"),
        ]
    )

    grade = grade_run(grammar.a_read_target(), units_of(grammar.a_report(chains=[chain])))

    assert grade.status == TargetStatus.MISSED


def test_nonce_carried_only_by_a_later_chain_step_is_a_proof():
    chain = grammar.a_chain(
        [
            grammar.a_step(),
            grammar.a_step(response=f"leaked {NONCE}"),
            grammar.a_step(arguments={"path": NONCE}),
        ]
    )

    grade = grade_run(grammar.a_read_target(), units_of(grammar.a_report(chains=[chain])))

    assert grade.status == TargetStatus.DETECTED


def test_nonce_only_in_the_server_command_is_not_a_proof():
    report = grammar.a_report(
        cases=[grammar.a_case(response="nothing")], server_command=f"docker run -e FLAG={NONCE}"
    )

    grade = grade_run(grammar.a_read_target(), units_of(report))

    assert grade.status == TargetStatus.MISSED
    assert not grade.surfaced


def test_nonce_only_in_a_step_observation_is_not_a_proof():
    chain = grammar.a_chain([grammar.a_step(response="nothing", observation=f"saw {NONCE}")])

    grade = grade_run(grammar.a_read_target(), units_of(grammar.a_report(chains=[chain])))

    assert grade.status == TargetStatus.MISSED


def test_nonce_under_pass_is_reached_but_judged_pass():
    case = grammar.a_case(response=f"leaked {NONCE}", verdict=grammar.PASS)

    grade = grade_run(grammar.a_read_target(), units_of(grammar.a_report(cases=[case])))

    assert grade.status == TargetStatus.REACHED_BUT_JUDGED_PASS
    assert grade.surfaced


def test_proof_and_fail_on_different_cases_is_not_detected():
    proof = grammar.a_case(response=f"leaked {NONCE}", verdict=grammar.PASS)
    fail = grammar.a_case(response="nothing", verdict=grammar.FAIL)

    grade = grade_run(grammar.a_read_target(), units_of(grammar.a_report(cases=[proof, fail])))

    assert grade.status == TargetStatus.REACHED_BUT_JUDGED_PASS


def test_nonce_under_fail_in_any_category_is_detected():
    case = grammar.a_case(response=f"leaked {NONCE}", category=grammar.RESOURCE_ABUSE)

    grade = grade_run(grammar.a_read_target(), units_of(grammar.a_report(cases=[case])))

    assert grade.status == TargetStatus.DETECTED
    assert grade.category == grammar.RESOURCE_ABUSE


@pytest.mark.parametrize(
    ("cases", "miss_kind"),
    [
        ([grammar.a_case(response="nothing")], MissKind.NOT_AIMED),
        ([grammar.a_blocked_case(AIMED)], MissKind.AIMED_BLOCKED),
        ([grammar.a_case(response="nothing", arguments=AIMED)], MissKind.AIMED_NO_PROOF),
        (
            [grammar.a_blocked_case(AIMED), grammar.a_case(response="nothing", arguments=AIMED)],
            MissKind.AIMED_NO_PROOF,
        ),
    ],
    ids=["not_aimed", "aimed_blocked", "aimed_no_proof", "blocked_and_unblocked"],
)
def test_a_missed_run_is_classed_by_its_best_aimed_unit(cases: list[TestCase], miss_kind: MissKind):
    grade = grade_run(grammar.a_read_target(), units_of(grammar.a_report(cases=cases)))

    assert grade.status == TargetStatus.MISSED
    assert grade.miss_kind == miss_kind


@pytest.mark.parametrize(
    ("case", "expected"),
    [
        (grammar.a_case(response="denied", arguments=AIMED, category=grammar.INJECTION), True),
        (
            grammar.a_case(response="denied", arguments=AIMED, category=grammar.RESOURCE_ABUSE),
            False,
        ),
        (grammar.a_case(response="denied", category=grammar.INJECTION), False),
    ],
    ids=["aimed_valid_category", "category_outside_class", "not_aimed"],
)
def test_fail_without_proof_needs_an_aimed_fail_in_a_valid_category(case: TestCase, expected: bool):
    grade = grade_run(grammar.a_read_target(), units_of(grammar.a_report(cases=[case])))

    assert grade.fail_without_proof is expected


@pytest.mark.parametrize(
    ("classes", "category", "expected"),
    [
        ((COMMAND_EXECUTION, READ_OUTSIDE_SCOPE), grammar.INFO_LEAKAGE, True),
        ((COMMAND_EXECUTION,), grammar.INFO_LEAKAGE, False),
        ((COMMAND_EXECUTION, INTERNAL_FETCH), grammar.INJECTION, True),
        ((COMMAND_EXECUTION, INTERNAL_FETCH), grammar.INFO_LEAKAGE, True),
        ((COMMAND_EXECUTION, INTERNAL_FETCH), grammar.INPUT_VALIDATION, False),
        ((), grammar.RESOURCE_ABUSE, True),
        ((), grammar.INPUT_VALIDATION, True),
    ],
    ids=[
        "union_admits_a_member_category",
        "one_class_does_not",
        "union_injection",
        "union_info_leakage",
        "union_input_validation",
        "no_class_resource_abuse",
        "no_class_input_validation",
    ],
)
def test_fail_without_proof_counts_a_category_any_class_of_the_set_admits(
    classes: tuple[FlawClass, ...], category: AuditCategory, expected: bool
):
    case = grammar.a_case(response="denied", arguments=AIMED, category=category)

    grade = grade_run(grammar.a_target_under(*classes), units_of(grammar.a_report(cases=[case])))

    assert grade.fail_without_proof is expected


def test_resolve_sums_a_union_target_fail_without_proof_runs():
    target = grammar.a_target_under(COMMAND_EXECUTION, READ_OUTSIDE_SCOPE)
    case = grammar.a_case(response="denied", arguments=AIMED, category=grammar.INFO_LEAKAGE)
    report = grammar.a_report(cases=[case])

    resolution = resolve([grade_run(target, units_of(report)) for _ in range(2)])

    assert resolution.fail_without_proof_runs == 2


@pytest.mark.parametrize(
    "arguments",
    [
        {"options": {"source": grammar.AIMED_PATH}},
        {"paths": ["/inside/a", grammar.AIMED_PATH]},
        {"batch": [{"files": [grammar.AIMED_PATH]}]},
    ],
    ids=["nested_dict", "list", "list_of_dicts"],
)
def test_aim_reads_nested_argument_values(arguments: dict[str, Any]):
    unit = unit_of_exchanges([(arguments, "ok")])

    assert is_aimed(unit, grammar.a_read_target().aim)


def test_non_string_argument_values_are_not_aimed():
    unit = unit_of_exchanges([({"depth": 3, "recursive": True, "path": None}, "ok")])

    assert not is_aimed(unit, grammar.a_read_target().aim)


def test_chain_blocked_at_its_first_step_is_aimed_blocked():
    chain = grammar.a_chain_blocked_at_first_step(AIMED)

    grade = grade_run(grammar.a_read_target(), units_of(grammar.a_report(chains=[chain])))

    assert grade.status == TargetStatus.MISSED
    assert grade.miss_kind == MissKind.AIMED_BLOCKED


def test_chain_blocked_after_a_leaking_first_step_is_detected():
    chain = grammar.a_chain(
        [grammar.a_step(response=f"leaked {NONCE}")], blocked_reason="destructive payload"
    )

    grade = grade_run(grammar.a_read_target(), units_of(grammar.a_report(chains=[chain])))

    assert grade.status == TargetStatus.DETECTED


def test_chain_blocked_after_its_first_step_is_a_blocked_judged_unit():
    chain = grammar.a_chain([grammar.a_step(arguments=AIMED)], blocked_reason="destructive payload")

    [unit] = units_of(grammar.a_report(chains=[chain]))

    assert unit.blocked
    assert unit.verdict == grammar.FAIL


def test_resolve_keeps_the_highest_rung_over_runs():
    resolution = resolve(
        [
            grammar.a_missed_run(MissKind.NOT_AIMED),
            grammar.a_reached_run(),
            grammar.a_detected_run(),
        ]
    )

    assert resolution.status == TargetStatus.DETECTED
    assert resolution.miss_kind is None
    assert resolution.evidence == f"leaked {NONCE}"
    assert resolution.category == grammar.INFO_LEAKAGE


def test_resolve_keeps_the_best_miss_class_over_missed_runs():
    resolution = resolve(
        [
            grammar.a_missed_run(MissKind.NOT_AIMED, aimed=False),
            grammar.a_missed_run(MissKind.AIMED_NO_PROOF),
            grammar.a_missed_run(MissKind.AIMED_BLOCKED),
        ]
    )

    assert resolution.status == TargetStatus.MISSED
    assert resolution.miss_kind == MissKind.AIMED_NO_PROOF


def test_resolve_counts_each_condition_per_run():
    resolution = resolve(
        [
            grammar.a_detected_run(),
            grammar.a_reached_run(),
            grammar.a_missed_run(MissKind.AIMED_NO_PROOF, fail_without_proof=True),
            grammar.a_missed_run(MissKind.NOT_AIMED, aimed=False),
        ]
    )

    assert resolution.detected_runs == 1
    assert resolution.surfaced_runs == 2
    assert resolution.aimed_runs == 3
    assert resolution.fail_without_proof_runs == 1


def test_unit_of_exchanges_finds_a_proof_in_the_last_output():
    unit = unit_of_exchanges(
        [({"path": "/a"}, "ok"), ({"path": "/b"}, "ok"), ({"path": "/c"}, f"leaked {NONCE}")]
    )

    assert proofs_in(unit, grammar.a_read_target()) == {PLACE: f"leaked {NONCE}"}


def test_unit_of_exchanges_reads_every_exchange_for_the_anti_echo():
    unit = unit_of_exchanges(
        [({"path": NONCE}, "ok"), ({"path": "/b"}, "ok"), ({"path": "/c"}, NONCE)]
    )

    assert proofs_in(unit, grammar.a_read_target()) == {}
