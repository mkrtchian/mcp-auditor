import math

import tests.unit.support.test_probe_given as given
import tests.unit.support.test_probe_then as then
from evals.probe import Bars, CallOutcome, admit, call_cost, reference_failures, summarize
from evals.probe_candidates import Prices
from mcp_auditor.domain.models import TokenUsage


class TestCallCost:
    def test_prices_cached_input_apart_from_the_rest_of_the_input(self):
        usage = TokenUsage(input_tokens=1_000_000, cached_input_tokens=400_000, output_tokens=0)
        prices = Prices(input=0.25, cached_input=0.025, output=1.50)

        assert math.isclose(call_cost(usage, prices), 0.6 * 0.25 + 0.4 * 0.025)

    def test_prices_output_at_the_output_price(self):
        usage = TokenUsage(output_tokens=100_000)
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
            given.an_observation(usage=TokenUsage(output_tokens=50, reasoning_tokens=30)),
            given.an_observation(usage=TokenUsage(output_tokens=50, reasoning_tokens=12)),
        ]

        stats = summarize(given.a_candidate(), observations, judge_weight=1.0)

        assert (stats.errors, stats.reasoning_tokens, stats.reasoning_expected) == (1, 42, True)


class TestAdmit:
    def test_admits_a_challenger_clean_on_every_bar(self):
        admission = admit(given.challenger_stats(), given.reference_stats(), Bars())

        then.admitted(admission)

    def test_rejects_a_parse_failure_naming_its_schema(self):
        stats = given.challenger_stats(parse_failures={"StepObservation": 1})

        admission = admit(stats, given.reference_stats(), Bars())

        then.rejected_for(admission, "1", "StepObservation")

    def test_rejects_a_refusal(self):
        stats = given.challenger_stats(refusals=1)

        admission = admit(stats, given.reference_stats(), Bars())

        then.rejected_for(admission, "1", "refusal")

    def test_rejects_an_error(self):
        stats = given.challenger_stats(errors=1)

        admission = admit(stats, given.reference_stats(), Bars())

        then.rejected_for(admission, "1", "error")

    def test_rejects_a_judge_median_above_three_times_the_reference(self):
        stats = given.challenger_stats(median_seconds={"main": 1.0, "judge": 3.1})

        admission = admit(stats, given.reference_stats(), Bars())

        then.rejected_for(admission, "judge", "3.10", "1.00")

    def test_admits_a_judge_median_at_exactly_three_times_the_reference(self):
        stats = given.challenger_stats(median_seconds={"main": 1.0, "judge": 3.0})

        admission = admit(stats, given.reference_stats(), Bars())

        then.admitted(admission)

    def test_rejects_a_cost_above_the_reference(self):
        stats = given.challenger_stats(weighted_cost=1.01)

        admission = admit(stats, given.reference_stats(), Bars())

        then.rejected_for(admission, "cost", "1.01", "1.00")

    def test_admits_a_cost_equal_to_the_reference(self):
        stats = given.challenger_stats(weighted_cost=1.0)

        admission = admit(stats, given.reference_stats(), Bars())

        then.admitted(admission)

    def test_rejects_reasoning_tokens_when_none_are_expected(self):
        stats = given.challenger_stats(reasoning_expected=False, reasoning_tokens=120)

        admission = admit(stats, given.reference_stats(), Bars())

        then.rejected_for(admission, "120", "reasoning")

    def test_rejects_no_reasoning_tokens_when_some_are_expected(self):
        stats = given.challenger_stats(reasoning_expected=True, reasoning_tokens=0)

        admission = admit(stats, given.reference_stats(), Bars())

        then.rejected_for(admission, "0", "reasoning")

    def test_skips_the_reasoning_check_without_an_expectation(self):
        stats = given.challenger_stats(reasoning_expected=None, reasoning_tokens=120)

        admission = admit(stats, given.reference_stats(), Bars())

        then.admitted(admission)


class TestReferenceFailures:
    def test_lists_the_bars_the_reference_fails(self):
        reference = given.reference_stats().model_copy(update={"errors": 2})

        failures = reference_failures(reference, Bars())

        assert len(failures) == 1
        assert "2" in failures[0]
