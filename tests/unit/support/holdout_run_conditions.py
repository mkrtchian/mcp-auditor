from datetime import date

from evals.cve.holdout_conditions import Cutoff, HoldoutConditions
from evals.pricing import Prices
from mcp_auditor.config import Settings

LUNA_PRICE = Prices(input=0.10, cached_input=0.01, output=0.50)
SETTINGS = Settings(provider="openai", model="gpt-6-luna", judge_model="", reasoning="none")


def ready_conditions() -> HoldoutConditions:
    return HoldoutConditions(
        chain_budget=3,
        max_chain_steps=5,
        tool_call_timeout=30,
        cutoffs={
            "gpt-6-luna": Cutoff(
                date=date(2026, 5, 18), type="training", source="https://example.test", note=None
            )
        },
        prices={"gpt-6-luna": LUNA_PRICE},
        prices_as_of=date(2026, 10, 15),
    )
