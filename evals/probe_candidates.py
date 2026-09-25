"""The models the probe measures, with their list prices and expected reasoning.

Every `Settings` names each field the probe depends on: a field left out is read
from `MCP_AUDITOR_*`, so an operator's judge override would otherwise become
every candidate's judge.
"""

from dataclasses import dataclass

from mcp_auditor.config import Settings

PRICES_DATE = "2026-09-24"


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


# Gemini `minimal` does not switch thinking fully off, so its tokens are not checked.
REFERENCE = Candidate(
    name="gemini-3.1-flash-lite minimal",
    settings=Settings(
        provider="google", model="gemini-3.1-flash-lite", judge_model="", reasoning="minimal"
    ),
    prices=Prices(input=0.25, cached_input=0.025, output=1.50),
    reasoning_expected=None,
)

CHALLENGERS = [
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
]

# Measured beside the reference and given no verdict: ADR 019 moves to it when no
# challenger is admitted, whatever bar it fails.
FALLBACK = Candidate(
    name="gemini-3.5-flash-lite minimal",
    settings=Settings(
        provider="google", model="gemini-3.5-flash-lite", judge_model="", reasoning="minimal"
    ),
    prices=Prices(input=0.30, cached_input=0.03, output=2.50),
    reasoning_expected=None,
)
