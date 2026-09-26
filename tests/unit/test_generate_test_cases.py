import tests.unit.support.test_generate_test_cases_given as given
import tests.unit.support.test_generate_test_cases_then as then
from mcp_auditor.domain import AuditCategory, TestCaseBatch
from mcp_auditor.domain.models import CoverageGap
from mcp_auditor.graph.nodes import make_generate_test_cases
from tests.fakes import FakeLLM


async def test_produces_pending_cases():
    batch = given.a_batch_of(3, categories=list(AuditCategory)[:3])
    node = make_generate_test_cases(FakeLLM([batch]))

    result = await node(given.a_generation_state(test_budget=3))

    then.pending_payloads_are(result, batch)
    assert result["judged_cases"] == []


async def test_a_complete_batch_is_kept_without_retry():
    batch = given.a_batch_of(5)
    node = make_generate_test_cases(FakeLLM([batch]))

    result = await node(given.a_generation_state(test_budget=5))

    then.pending_payloads_are(result, batch)
    then.token_usage_count(result, 1)
    assert result["coverage_gap"] is None


async def test_an_incomplete_batch_is_retried_once():
    retried = given.a_batch_of(5)
    node = make_generate_test_cases(FakeLLM([given.a_batch_of(4), retried]))

    result = await node(given.a_generation_state(test_budget=5))

    then.pending_payloads_are(result, retried)
    then.token_usage_count(result, 2)
    assert result["coverage_gap"] is None


async def test_a_retry_still_incomplete_is_kept_with_its_gap():
    retried = given.a_batch_of(3)
    completion = given.a_batch_of(1)
    node = make_generate_test_cases(FakeLLM([given.a_batch_of(4), retried, completion]))

    result = await node(given.a_generation_state(test_budget=5))

    then.pending_payloads_are(result, retried)
    then.token_usage_count(result, 3)
    assert result["coverage_gap"] == CoverageGap(
        requested_cases=5,
        received_cases=3,
        missing_categories=[AuditCategory.INFO_LEAKAGE, AuditCategory.RESOURCE_ABUSE],
    )


async def test_a_completion_fills_the_category_the_retry_missed():
    retried = given.a_batch_of(4)
    completion = given.a_batch_of(1, categories=[AuditCategory.RESOURCE_ABUSE])
    node = make_generate_test_cases(FakeLLM([retried, retried, completion]))

    result = await node(given.a_generation_state(test_budget=5))

    then.pending_payloads_are(result, TestCaseBatch(cases=[*retried.cases, *completion.cases]))
    then.token_usage_count(result, 3)
    assert result["coverage_gap"] is None


async def test_a_partial_completion_leaves_only_the_unfilled_category_missing():
    retried = given.a_batch_of(3)
    completion = given.a_batch_of(1, categories=[AuditCategory.INFO_LEAKAGE])
    node = make_generate_test_cases(FakeLLM([retried, retried, completion]))

    result = await node(given.a_generation_state(test_budget=5))

    assert result["coverage_gap"] == CoverageGap(
        requested_cases=5, received_cases=4, missing_categories=[AuditCategory.RESOURCE_ABUSE]
    )


async def test_a_completion_drops_cases_in_categories_already_covered():
    retried = given.a_batch_of(4)
    missing_case = given.a_payload(AuditCategory.RESOURCE_ABUSE)
    completion = TestCaseBatch(cases=[given.a_payload(), missing_case])
    node = make_generate_test_cases(FakeLLM([retried, retried, completion]))

    result = await node(given.a_generation_state(test_budget=5))

    then.pending_payloads_are(result, TestCaseBatch(cases=[*retried.cases, missing_case]))


async def test_a_completion_is_cut_to_its_share_of_the_budget():
    retried = given.a_batch_of(4)
    completion = given.a_batch_of(3, categories=[AuditCategory.RESOURCE_ABUSE])
    node = make_generate_test_cases(FakeLLM([retried, retried, completion]))

    result = await node(given.a_generation_state(test_budget=5))

    then.pending_payloads_are(result, TestCaseBatch(cases=[*retried.cases, completion.cases[0]]))


async def test_a_retry_short_of_cases_only_is_not_completed():
    retried = given.a_batch_of(5)
    node = make_generate_test_cases(FakeLLM([retried, retried]))

    result = await node(given.a_generation_state(test_budget=6))

    then.pending_payloads_are(result, retried)
    then.token_usage_count(result, 2)
    assert result["coverage_gap"] == CoverageGap(
        requested_cases=6, received_cases=5, missing_categories=[]
    )
