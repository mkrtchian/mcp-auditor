"""The models the probe measures, with their list prices and expected reasoning.

Every `Settings` names each field the probe depends on: a field left out is read
from `MCP_AUDITOR_*`, so an operator's judge override would otherwise become
every candidate's judge.
"""

from dataclasses import dataclass

from mcp_auditor.config import Settings

PRICES_DATE = "2026-10-15"


@dataclass(frozen=True)
class Prices:
    """Dollars per million tokens, as listed on PRICES_DATE."""

    input: float
    cached_input: float
    output: float


@dataclass(frozen=True)
class Candidate:
    name: str
    settings: Settings
    prices: Prices
    # True: reasoning tokens > 0 over the corpus. False: 0. None: not checked.
    reasoning_expected: bool | None


# The settings the corpus is captured on, and the denominator of the cost ratio.
# Gemini `minimal` does not switch thinking fully off, so its tokens are not checked.
REFERENCE = Candidate(
    name="gemini-3.1-flash-lite minimal",
    settings=Settings(
        provider="google", model="gemini-3.1-flash-lite", judge_model="", reasoning="minimal"
    ),
    prices=Prices(input=0.25, cached_input=0.025, output=1.50),
    reasoning_expected=None,
)

CANDIDATES = [
    Candidate(
        name="gpt-6-luna none",
        settings=Settings(provider="openai", model="gpt-6-luna", judge_model="", reasoning="none"),
        prices=Prices(input=0.10, cached_input=0.01, output=0.50),
        reasoning_expected=False,
    ),
    Candidate(
        name="gpt-6-luna low",
        settings=Settings(provider="openai", model="gpt-6-luna", judge_model="", reasoning="low"),
        prices=Prices(input=0.10, cached_input=0.01, output=0.50),
        reasoning_expected=True,
    ),
    Candidate(
        name="gemini-3.5-flash-lite minimal",
        settings=Settings(
            provider="google", model="gemini-3.5-flash-lite", judge_model="", reasoning="minimal"
        ),
        prices=Prices(input=0.30, cached_input=0.03, output=2.50),
        reasoning_expected=None,
    ),
    Candidate(
        name="claude-haiku-5-5 none",
        settings=Settings(
            provider="anthropic", model="claude-haiku-5-5", judge_model="", reasoning="none"
        ),
        prices=Prices(input=0.10, cached_input=0.01, output=0.50),
        reasoning_expected=False,
    ),
    Candidate(
        name="claude-haiku-5-5 low",
        settings=Settings(
            provider="anthropic", model="claude-haiku-5-5", judge_model="", reasoning="low"
        ),
        prices=Prices(input=0.10, cached_input=0.01, output=0.50),
        reasoning_expected=True,
    ),
    Candidate(
        name="glm-5.3 low sail-research",
        settings=Settings(
            provider="openrouter",
            model="z-ai/glm-5.3",
            judge_model="",
            reasoning="low",
            openrouter_hosts="sail-research",
        ),
        prices=Prices(input=0.15, cached_input=0.14, output=3.40),
        reasoning_expected=True,
    ),
    Candidate(
        name="glm-5.3 low deepinfra-fp4",
        settings=Settings(
            provider="openrouter",
            model="z-ai/glm-5.3",
            judge_model="",
            reasoning="low",
            openrouter_hosts="deepinfra/fp4",
        ),
        prices=Prices(input=0.5625, cached_input=0.125, output=2.50),
        reasoning_expected=True,
    ),
]
