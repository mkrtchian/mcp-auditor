import tests.unit.support.test_cve_grammar_given as grammar_given
import tests.unit.support.test_nuisance_counter_given as given
from evals import cve_baseline
from evals.cve_grammar import VALID_CATEGORIES, MechanismClass
from evals.cve_units import JudgeCategory, Verdict
from evals.nuisance_counter import (
    ToolVerdict,
    counter_fingerprint,
    flagged_tools,
    raw_fail_count,
    tool_verdicts,
)

_READ_CATEGORIES = VALID_CATEGORIES[MechanismClass.READ_OUTSIDE_SCOPE]
_EXEC_CATEGORIES = VALID_CATEGORIES[MechanismClass.COMMAND_EXECUTION]
_INFO_LEAKAGE = JudgeCategory(grammar_given.INFO_LEAKAGE.value)
_INJECTION = JudgeCategory(grammar_given.INJECTION.value)


def test_every_case_and_chain_gives_a_verdict_carrying_its_tool():
    report = given.a_report_of_tools(
        given.a_tool_report(
            "read_file",
            cases=[
                grammar_given.a_case(),
                grammar_given.a_case(verdict=None),
            ],
            chains=[grammar_given.a_chain([grammar_given.a_step()], verdict=grammar_given.PASS)],
        ),
        given.a_tool_report(
            "list_dir", cases=[grammar_given.a_case(category=grammar_given.INJECTION)]
        ),
    )

    assert tool_verdicts(report) == [
        ToolVerdict("read_file", _INFO_LEAKAGE, Verdict.FAIL),
        ToolVerdict("read_file", None, None),
        ToolVerdict("read_file", _INFO_LEAKAGE, Verdict.PASS),
        ToolVerdict("list_dir", _INJECTION, Verdict.FAIL),
    ]


def test_a_counted_tool_failing_in_an_admitted_category_is_flagged():
    report = grammar_given.a_report(cases=[grammar_given.a_case()])

    assert flagged_tools(report, {"read_file": _READ_CATEGORIES}) == {"read_file"}


def test_a_counted_tool_failing_outside_its_categories_is_not_flagged():
    report = grammar_given.a_report(cases=[grammar_given.a_case()])

    assert _INFO_LEAKAGE not in _EXEC_CATEGORIES
    assert flagged_tools(report, {"read_file": _EXEC_CATEGORIES}) == frozenset()


def test_a_fail_on_a_tool_that_is_not_counted_flags_nothing():
    report = given.a_report_of_tools(
        given.a_tool_report("read_file", cases=[grammar_given.a_case(verdict=grammar_given.PASS)]),
        given.a_tool_report("list_dir", cases=[grammar_given.a_case()]),
    )

    assert flagged_tools(report, {"read_file": _READ_CATEGORIES}) == frozenset()


def test_a_counted_tool_whose_cases_all_pass_is_not_flagged():
    report = grammar_given.a_report(cases=[grammar_given.a_case(verdict=grammar_given.PASS)] * 2)

    assert flagged_tools(report, {"read_file": _READ_CATEGORIES}) == frozenset()


def test_a_chain_judged_fail_flags_its_counted_tool():
    report = grammar_given.a_report(chains=[grammar_given.a_chain([grammar_given.a_step()])])

    assert flagged_tools(report, {"read_file": _READ_CATEGORIES}) == {"read_file"}


def test_the_raw_count_takes_every_fail_on_every_tool():
    report = given.a_report_of_tools(
        given.a_tool_report(
            "read_file",
            cases=[grammar_given.a_case(), grammar_given.a_case(verdict=grammar_given.PASS)],
            chains=[grammar_given.a_chain([grammar_given.a_step()])],
        ),
        given.a_tool_report(
            "list_dir", cases=[grammar_given.a_case(category=grammar_given.RESOURCE_ABUSE)]
        ),
    )

    assert raw_fail_count(report) == 3


def test_the_raw_count_of_a_report_with_no_judged_case_is_zero():
    report = grammar_given.a_report(cases=[grammar_given.a_case(verdict=None)])

    assert raw_fail_count(report) == 0


def test_the_counter_fingerprint_is_a_stable_digest_apart_from_the_grammars():
    fingerprint = counter_fingerprint()

    assert fingerprint == counter_fingerprint()
    assert len(fingerprint) == 64
    assert set(fingerprint) <= set("0123456789abcdef")
    assert fingerprint != cve_baseline.grammar_fingerprint()
