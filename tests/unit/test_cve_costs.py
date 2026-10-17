import pytest

import tests.unit.support.test_cve_costs_given as given
from evals.cve_costs import large_request_targets, render_cost_table, target_costs


def test_equal_prices_split_the_cost_by_phase_and_total_it_from_the_total_usage():
    by_target = {"CVE-1": given.a_phase_usage(total=1_000_000, chain=600_000, judge=300_000)}

    [cost] = target_costs(by_target, given.ONE_DOLLAR_PER_MILLION, given.ONE_DOLLAR_PER_MILLION)

    assert cost.single_step == pytest.approx(0.4)
    assert cost.chains == pytest.approx(0.6)
    assert cost.judge == pytest.approx(0.3)
    assert cost.total == pytest.approx(1.0)  # not 0.4 + 0.6 + 0.3: the chain judgment overlaps


def test_a_judge_priced_apart_keeps_total_and_judge_exact_by_role_and_leaves_phases_unsplit():
    by_target = {"CVE-1": given.a_phase_usage(total=1_000_000, chain=600_000, judge=300_000)}

    [cost] = target_costs(by_target, given.ONE_DOLLAR_PER_MILLION, given.TEN_DOLLARS_PER_MILLION)

    assert cost.judge == pytest.approx(3.0)
    assert cost.total == pytest.approx(0.7 + 3.0)
    assert (cost.single_step, cost.chains) == (None, None)


def test_a_target_cost_carries_its_largest_request():
    by_target = {"CVE-1": given.a_phase_usage(10, 0, 0, largest_request=7)}

    [cost] = target_costs(by_target, given.ONE_DOLLAR_PER_MILLION, given.ONE_DOLLAR_PER_MILLION)

    assert cost.largest_input_tokens == 7


def test_the_cost_table_has_one_row_per_target_with_tokens_and_largest_request():
    by_target = {
        "CVE-1": given.a_phase_usage(1_000_000, 0, 0, largest_request=4_321),
        "CVE-2": given.a_phase_usage(2_000_000, 0, 0),
    }
    costs = target_costs(by_target, given.ONE_DOLLAR_PER_MILLION, given.TEN_DOLLARS_PER_MILLION)

    rows = [line for line in render_cost_table(costs) if line.startswith("| CVE-")]

    assert len(rows) == 2
    assert "| CVE-1 | 1000000 | 0 | 4321 | - | - |" in rows[0]


def test_only_the_targets_with_a_request_above_the_tiered_threshold_are_named():
    by_target = {
        "CVE-1": given.a_phase_usage(10, 0, 0, largest_request=100_001),
        "CVE-2": given.a_phase_usage(10, 0, 0, largest_request=100_000),
    }
    costs = target_costs(by_target, given.ONE_DOLLAR_PER_MILLION, given.ONE_DOLLAR_PER_MILLION)

    assert large_request_targets(costs) == ["CVE-1"]
