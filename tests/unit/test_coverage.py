import tests.unit.support.test_coverage_given as given
from mcp_auditor.domain import AuditCategory
from mcp_auditor.domain.coverage import find_coverage_gap
from mcp_auditor.domain.models import CoverageGap

ALL_CATEGORIES = list(AuditCategory)


def test_a_complete_batch_has_no_gap():
    batch = given.a_batch_of(10)

    assert find_coverage_gap(batch, budget=10, categories=ALL_CATEGORIES) is None


def test_a_short_batch_reports_requested_and_received_cases():
    batch = given.a_batch_of(9)

    gap = find_coverage_gap(batch, budget=10, categories=ALL_CATEGORIES)

    assert gap == CoverageGap(requested_cases=10, received_cases=9, missing_categories=[])


def test_a_batch_leaving_out_a_category_reports_it_missing():
    covered = [category for category in ALL_CATEGORIES if category != AuditCategory.INFO_LEAKAGE]
    batch = given.a_batch_of(10, categories=covered)

    gap = find_coverage_gap(batch, budget=10, categories=ALL_CATEGORIES)

    assert gap == CoverageGap(
        requested_cases=10, received_cases=10, missing_categories=[AuditCategory.INFO_LEAKAGE]
    )


def test_a_budget_below_the_category_count_needs_as_many_categories_as_cases():
    batch = given.a_batch_of(3, categories=ALL_CATEGORIES[:3])

    assert find_coverage_gap(batch, budget=3, categories=ALL_CATEGORIES) is None


def test_a_small_budget_short_of_distinct_categories_lists_every_absent_one():
    batch = given.a_batch_of(3, categories=ALL_CATEGORIES[:2])

    gap = find_coverage_gap(batch, budget=3, categories=ALL_CATEGORIES)

    assert gap == CoverageGap(
        requested_cases=3, received_cases=3, missing_categories=ALL_CATEGORIES[2:]
    )


def test_more_cases_than_the_budget_is_not_a_gap():
    batch = given.a_batch_of(11)

    assert find_coverage_gap(batch, budget=10, categories=ALL_CATEGORIES) is None


def test_a_single_case_budget_never_reports_a_category_gap():
    batch = given.a_batch_of(1, categories=[AuditCategory.RESOURCE_ABUSE])

    assert find_coverage_gap(batch, budget=1, categories=ALL_CATEGORIES) is None
