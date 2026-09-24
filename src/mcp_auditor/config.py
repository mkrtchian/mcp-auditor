from dataclasses import dataclass

from dotenv import load_dotenv
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    model_config = {"env_prefix": "MCP_AUDITOR_"}

    provider: str = "google"
    model: str = ""
    judge_model: str = ""
    reasoning: str = ""
    langsmith_project: str = "mcp-auditor"
    tool_call_timeout: int = 30

    def resolve_model(self) -> str:
        if self.model:
            return self.model
        return _default_model(self.provider)

    def resolve_judge_model(self) -> str:
        if self.judge_model:
            return self.judge_model
        return self.resolve_model()

    def resolve_reasoning(self, model: str) -> str | None:
        defaults = _provider_defaults(self.provider)
        if self.reasoning:
            _check_reasoning_accepted(self.provider, defaults, self.reasoning)
            return self.reasoning
        if model == defaults.model:
            return defaults.reasoning
        return None


@dataclass(frozen=True)
class _ProviderDefaults:
    model: str
    reasoning: str | None
    accepted_reasoning: tuple[str, ...]


_PROVIDERS = {
    "google": _ProviderDefaults(
        model="gemini-3.1-flash-lite",
        reasoning="minimal",
        accepted_reasoning=("minimal", "low", "medium", "high"),
    ),
    "anthropic": _ProviderDefaults(
        model="claude-haiku-4-5-20251001",
        reasoning=None,
        accepted_reasoning=(),
    ),
}


def _default_model(provider: str) -> str:
    return _provider_defaults(provider).model


def _provider_defaults(provider: str) -> _ProviderDefaults:
    if provider not in _PROVIDERS:
        raise ValueError(f"Unknown provider: {provider!r}. Use 'google' or 'anthropic'.")
    return _PROVIDERS[provider]


def _check_reasoning_accepted(provider: str, defaults: _ProviderDefaults, reasoning: str) -> None:
    if reasoning in defaults.accepted_reasoning:
        return
    if not defaults.accepted_reasoning:
        raise ValueError(f"Provider {provider!r} takes no reasoning setting, got {reasoning!r}.")
    accepted = ", ".join(defaults.accepted_reasoning)
    raise ValueError(
        f"Reasoning {reasoning!r} is not accepted by provider {provider!r}. Use one of: {accepted}."
    )


def load_settings() -> Settings:
    load_dotenv()
    return Settings()
