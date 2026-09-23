import tests.unit.support.test_eval_baseline_given as given
from evals.eval_session import ci_condition_mismatches


def test_the_ci_conditions_have_no_mismatch():
    assert ci_condition_mismatches(given.conditions()) == []


def test_a_budget_other_than_the_ci_one_is_named():
    mismatches = ci_condition_mismatches(given.conditions(budget=7))

    assert mismatches == ["budget: CI runs 10, this run 7"]


def test_a_model_override_is_named():
    conditions = given.conditions().model_copy(update={"judge_model": "claude-haiku-4-5"})

    mismatches = ci_condition_mismatches(conditions)

    assert mismatches == ["judge_model: CI runs gemini-3.1-flash-lite, this run claude-haiku-4-5"]
