from pathlib import Path

import tests.unit.support.grammar_inputs as grammar
from evals.baseline import fingerprint_sources
from evals.cve.grammar import VALID_CATEGORIES, FlawClass
from evals.cve.nuisance import counter, counting
from evals.cve.nuisance.counter import (
    ToolVerdict,
    counter_fingerprint,
    fail_count_on,
    flagged_tools,
    raw_fail_count,
    tool_verdicts,
)
from evals.cve.units import JudgeCategory, Verdict

_READ_CATEGORIES = VALID_CATEGORIES[FlawClass.READ_OUTSIDE_SCOPE]
_EXEC_CATEGORIES = VALID_CATEGORIES[FlawClass.COMMAND_EXECUTION]
_INFO_LEAKAGE = JudgeCategory(grammar.INFO_LEAKAGE.value)
_INJECTION = JudgeCategory(grammar.INJECTION.value)


def test_every_case_and_chain_gives_a_verdict_carrying_its_tool():
    report = grammar.a_report_of_tools(
        grammar.a_tool_report(
            "read_file",
            cases=[
                grammar.a_case(),
                grammar.a_case(verdict=None),
            ],
            chains=[grammar.a_chain([grammar.a_step()], verdict=grammar.PASS)],
        ),
        grammar.a_tool_report("list_dir", cases=[grammar.a_case(category=grammar.INJECTION)]),
    )

    assert tool_verdicts(report) == [
        ToolVerdict("read_file", _INFO_LEAKAGE, Verdict.FAIL),
        ToolVerdict("read_file", None, None),
        ToolVerdict("read_file", _INFO_LEAKAGE, Verdict.PASS),
        ToolVerdict("list_dir", _INJECTION, Verdict.FAIL),
    ]


def test_a_counted_tool_failing_in_an_admitted_category_is_flagged():
    report = grammar.a_report(cases=[grammar.a_case()])

    assert flagged_tools(report, {"read_file": _READ_CATEGORIES}) == {"read_file"}


def test_a_counted_tool_failing_outside_its_categories_is_not_flagged():
    report = grammar.a_report(cases=[grammar.a_case()])

    assert _INFO_LEAKAGE not in _EXEC_CATEGORIES
    assert flagged_tools(report, {"read_file": _EXEC_CATEGORIES}) == frozenset()


def test_a_fail_on_a_tool_that_is_not_counted_flags_nothing():
    report = grammar.a_report_of_tools(
        grammar.a_tool_report("read_file", cases=[grammar.a_case(verdict=grammar.PASS)]),
        grammar.a_tool_report("list_dir", cases=[grammar.a_case()]),
    )

    assert flagged_tools(report, {"read_file": _READ_CATEGORIES}) == frozenset()


def test_a_counted_tool_whose_cases_all_pass_is_not_flagged():
    report = grammar.a_report(cases=[grammar.a_case(verdict=grammar.PASS)] * 2)

    assert flagged_tools(report, {"read_file": _READ_CATEGORIES}) == frozenset()


def test_a_chain_judged_fail_flags_its_counted_tool():
    report = grammar.a_report(chains=[grammar.a_chain([grammar.a_step()])])

    assert flagged_tools(report, {"read_file": _READ_CATEGORIES}) == {"read_file"}


def test_the_raw_count_takes_every_fail_on_every_tool():
    report = grammar.a_report_of_tools(
        grammar.a_tool_report(
            "read_file",
            cases=[grammar.a_case(), grammar.a_case(verdict=grammar.PASS)],
            chains=[grammar.a_chain([grammar.a_step()])],
        ),
        grammar.a_tool_report("list_dir", cases=[grammar.a_case(category=grammar.RESOURCE_ABUSE)]),
    )

    assert raw_fail_count(report) == 3


def test_the_raw_count_of_a_report_with_no_judged_case_is_zero():
    report = grammar.a_report(cases=[grammar.a_case(verdict=None)])

    assert raw_fail_count(report) == 0


def test_the_count_on_listed_tools_takes_each_fail_on_a_listed_tool_in_its_categories():
    report = grammar.a_report_of_tools(
        grammar.a_tool_report(
            "read_file",
            cases=[
                grammar.a_case(),
                grammar.a_case(category=grammar.RESOURCE_ABUSE),
                grammar.a_case(verdict=grammar.PASS),
            ],
            chains=[grammar.a_chain([grammar.a_step()])],
        ),
        grammar.a_tool_report("list_dir", cases=[grammar.a_case()]),
    )

    assert JudgeCategory(grammar.RESOURCE_ABUSE.value) not in _READ_CATEGORIES
    assert fail_count_on(report, {"read_file": _READ_CATEGORIES}) == 2


def test_the_counter_fingerprint_covers_the_verdict_predicate_and_the_counted_tool_derivation():
    sources = [
        Path(counter.__file__).read_text(),
        Path(counting.__file__).read_text(),
    ]

    assert counter_fingerprint() == fingerprint_sources(sources)
