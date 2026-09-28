import math

import tests.unit.support.test_probe_given as given
import tests.unit.support.test_probe_then as then
from evals.probe import (
    CallOutcome,
    ProbeObservation,
    call_cost,
    count_defects,
    list_defects,
    summarize,
)
from evals.probe_candidates import Prices
from mcp_auditor.domain.models import ProviderUsage


class TestCallCost:
    def test_prices_cached_input_apart_from_the_rest_of_the_input(self):
        usage = ProviderUsage(input_tokens=1_000_000, cached_input_tokens=400_000, output_tokens=0)
        prices = Prices(input=0.25, cached_input=0.025, output=1.50)

        assert math.isclose(call_cost(usage, prices), 0.6 * 0.25 + 0.4 * 0.025)

    def test_prices_output_at_the_output_price(self):
        usage = ProviderUsage(output_tokens=100_000)
        prices = Prices(input=0.25, cached_input=0.025, output=1.50)

        assert math.isclose(call_cost(usage, prices), 0.15)


class TestSummarize:
    def test_weights_judge_calls_and_leaves_the_others_at_one(self):
        observations = [
            given.an_observation(role="main", usage=given.a_million_input_tokens()),
            given.an_observation(
                role="judge", schema_name="Judgment", usage=given.a_million_input_tokens()
            ),
        ]

        stats = summarize(given.a_candidate(), observations, judge_weight=2.5)

        assert math.isclose(stats.weighted_cost, 1.0 + 2.5)

    def test_counts_the_cost_of_a_parse_failure_like_a_parsed_call(self):
        usage = ProviderUsage(input_tokens=1_000, output_tokens=8_192)
        prices = Prices(input=0.25, cached_input=0.025, output=1.50)
        observations = [
            given.an_observation(usage=usage),
            given.an_observation(outcome=CallOutcome.PARSE_FAILURE, usage=usage),
        ]

        stats = summarize(given.a_candidate(prices), observations, judge_weight=1.0)

        assert math.isclose(stats.weighted_cost, 2 * call_cost(usage, prices))

    def test_computes_the_median_latency_of_each_role(self):
        observations = [
            given.an_observation(role="main", seconds=1.0),
            given.an_observation(role="main", seconds=2.0),
            given.an_observation(role="main", seconds=9.0),
            given.an_observation(role="judge", schema_name="Judgment", seconds=4.0),
            given.an_observation(role="judge", schema_name="Judgment", seconds=6.0),
        ]

        stats = summarize(given.a_candidate(), observations, judge_weight=1.0)

        assert stats.median_seconds == {"main": 2.0, "judge": 5.0}

    def test_counts_parse_failures_per_schema(self):
        observations = [
            given.an_observation(schema_name="StepObservation", outcome=CallOutcome.PARSE_FAILURE),
            given.an_observation(schema_name="StepObservation", outcome=CallOutcome.PARSE_FAILURE),
            given.an_observation(schema_name="TestCaseBatch", outcome=CallOutcome.PARSE_FAILURE),
            given.an_observation(schema_name="Judgment"),
        ]

        stats = summarize(given.a_candidate(), observations, judge_weight=1.0)

        assert stats.parse_failures == {"StepObservation": 2, "TestCaseBatch": 1}

    def test_counts_coverage_gaps_and_unparsed_batches_as_refusals(self):
        observations = [
            given.an_observation(coverage_gap=given.a_coverage_gap()),
            given.an_observation(outcome=CallOutcome.PARSE_FAILURE),
            given.an_observation(),
            given.an_observation(schema_name="Judgment", outcome=CallOutcome.PARSE_FAILURE),
        ]

        stats = summarize(given.a_candidate(), observations, judge_weight=1.0)

        assert stats.refusals == 2

    def test_counts_errors_and_sums_reasoning_tokens(self):
        observations = [
            given.an_observation(outcome=CallOutcome.ERROR, error="timeout"),
            given.an_observation(usage=ProviderUsage(output_tokens=50, reasoning_tokens=30)),
            given.an_observation(usage=ProviderUsage(output_tokens=50, reasoning_tokens=12)),
        ]

        stats = summarize(given.a_candidate(), observations, judge_weight=1.0)

        assert (stats.errors, stats.reasoning_tokens, stats.reasoning_expected) == (1, 42, True)


class TestCountDefects:
    def test_counts_each_kind_of_defect_over_the_observations_given(self):
        observations = [
            given.an_observation(role="judge", schema_name="Judgment"),
            given.an_observation(outcome=CallOutcome.PARSE_FAILURE),
            given.an_observation(
                role="judge",
                schema_name="Judgment",
                outcome=CallOutcome.PARSE_FAILURE,
                truncated_attempts=2,
            ),
            given.an_observation(coverage_gap=given.a_coverage_gap()),
            given.an_observation(outcome=CallOutcome.ERROR, error="timeout"),
        ]

        counts = count_defects("candidate", observations)

        assert counts.model_dump() == {
            "candidate": "candidate",
            "calls": 5,
            "parse_failures": 2,
            "parse_failures_with_truncation": 1,
            "refusals": 2,
            "errors": 1,
        }


class TestProbeObservation:
    def test_a_line_written_before_truncation_was_recorded_reads_as_no_truncation(self):
        line = given.an_observation(outcome=CallOutcome.PARSE_FAILURE).model_dump_json(
            exclude={"truncated_attempts"}
        )

        assert ProbeObservation.model_validate_json(line).truncated_attempts == 0


class TestListDefects:
    def test_lists_no_defect_for_a_clean_candidate(self):
        assert list_defects(given.candidate_stats()) == []

    def test_lists_a_parse_failure_with_its_count_and_its_schema(self):
        defects = list_defects(given.candidate_stats(parse_failures={"StepObservation": 1}))

        then.lists_defects(defects, "1", "StepObservation")

    def test_lists_a_refusal_with_its_count(self):
        defects = list_defects(given.candidate_stats(refusals=1))

        then.lists_defects(defects, "1", "refusal")

    def test_lists_an_error_with_its_count_and_asks_for_a_rerun(self):
        defects = list_defects(given.candidate_stats(errors=1))

        then.lists_defects(defects, "1", "rerun")

    def test_lists_reasoning_tokens_where_the_setting_expects_none(self):
        stats = given.candidate_stats(reasoning_expected=False, reasoning_tokens=120)

        then.lists_defects(list_defects(stats), "120", "reasoning")

    def test_lists_no_reasoning_token_where_the_setting_expects_some(self):
        stats = given.candidate_stats(reasoning_expected=True, reasoning_tokens=0)

        then.lists_defects(list_defects(stats), "0", "reasoning")

    def test_skips_the_reasoning_check_without_an_expectation(self):
        stats = given.candidate_stats(reasoning_expected=None, reasoning_tokens=120)

        assert list_defects(stats) == []

    def test_never_lists_cost_or_latency_whatever_their_values(self):
        stats = given.candidate_stats(
            weighted_cost=10.0, median_seconds={"main": 10.0, "judge": 10.0}
        )

        assert list_defects(stats) == []
