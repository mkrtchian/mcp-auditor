from datetime import date

from evals.cve.holdout_conditions import CONDITIONS_PATH, load_conditions
from evals.pricing import Prices


def test_the_committed_file_is_ready_for_the_logged_models():
    conditions = load_conditions(CONDITIONS_PATH)

    assert conditions.chain_budget == 3
    assert conditions.max_chain_steps == 3
    assert conditions.tool_call_timeout == 60
    assert conditions.cutoffs["gpt-6-luna"].date == date(2026, 5, 18)
    assert conditions.prices["gpt-6-luna"] == Prices(input=0.10, cached_input=0.01, output=0.50)
    assert conditions.cutoffs["claude-haiku-5-5"].date == date(2026, 6, 30)
    assert conditions.prices["claude-haiku-5-5"] == Prices(
        input=0.10, cached_input=0.01, output=0.50
    )

    conditions.require_ready(["gpt-6-luna", "claude-haiku-5-5"])
