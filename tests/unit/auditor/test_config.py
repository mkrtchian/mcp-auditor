import pytest

from mcp_auditor.config import Settings


def test_an_empty_environment_selects_the_anthropic_provider(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("MCP_AUDITOR_PROVIDER", raising=False)
    monkeypatch.delenv("MCP_AUDITOR_MODEL", raising=False)
    monkeypatch.delenv("MCP_AUDITOR_JUDGE_MODEL", raising=False)
    monkeypatch.delenv("MCP_AUDITOR_REASONING", raising=False)

    settings = Settings()

    assert settings.provider == "anthropic"
    assert settings.resolve_judge_model() == settings.resolve_model()


def test_the_provider_is_read_from_the_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MCP_AUDITOR_PROVIDER", "google")

    assert Settings().provider == "google"


def test_model_override(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MCP_AUDITOR_PROVIDER", "google")
    monkeypatch.setenv("MCP_AUDITOR_MODEL", "gemini-pro")

    settings = Settings()

    assert settings.resolve_model() == "gemini-pro"


def test_judge_model_fallback(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MCP_AUDITOR_MODEL", "gemini-pro")
    monkeypatch.delenv("MCP_AUDITOR_JUDGE_MODEL", raising=False)

    settings = Settings()

    assert settings.resolve_judge_model() == "gemini-pro"


def test_judge_model_override(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MCP_AUDITOR_MODEL", "flash")
    monkeypatch.setenv("MCP_AUDITOR_JUDGE_MODEL", "pro")

    settings = Settings()

    assert settings.resolve_judge_model() == "pro"


def test_unknown_provider_names_every_provider(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MCP_AUDITOR_PROVIDER", "mistral")
    monkeypatch.delenv("MCP_AUDITOR_MODEL", raising=False)

    settings = Settings()

    with pytest.raises(ValueError, match="Unknown provider") as error:
        settings.resolve_model()
    for provider in ("google", "anthropic", "openai", "fireworks", "alibaba", "openrouter"):
        assert provider in str(error.value)


@pytest.mark.parametrize(
    ("provider", "model", "reasoning"),
    [
        ("google", "gemini-3.5-flash-lite", "minimal"),
        ("anthropic", "claude-haiku-5-5", "low"),
        ("openai", "gpt-6-luna", "none"),
        ("fireworks", "accounts/fireworks/models/glm-5p3-flash", "medium"),
        ("alibaba", "qwen3.8-flash", None),
        ("openrouter", "z-ai/glm-5.3", "low"),
    ],
)
def test_each_provider_resolves_its_default_model_at_its_default_reasoning(
    provider: str, model: str, reasoning: str | None
) -> None:
    settings = _settings(provider)

    assert settings.resolve_model() == model
    assert settings.resolve_reasoning(model) == reasoning


def _settings(provider: str, reasoning: str = "") -> Settings:
    return Settings(provider=provider, model="", judge_model="", reasoning=reasoning)


def test_a_model_other_than_the_default_resolves_no_reasoning_when_unset() -> None:
    assert _settings("google").resolve_reasoning("gemini-3.1-pro-preview") is None


def test_a_model_other_than_the_default_takes_the_explicit_reasoning() -> None:
    settings = _settings("google", reasoning="high")

    assert settings.resolve_reasoning("gemini-3.1-pro-preview") == "high"


def test_an_accepted_explicit_reasoning_is_returned_as_set() -> None:
    settings = _settings("google", reasoning="low")

    assert settings.resolve_reasoning(settings.resolve_model()) == "low"


@pytest.mark.parametrize(
    ("provider", "reasoning", "accepted"),
    [
        ("google", "max", "minimal, low, medium, high"),
        ("anthropic", "minimal", "none, low, medium, high, xhigh, max"),
        ("openai", "minimal", "none, low, medium, high, xhigh, max"),
        ("openrouter", "extreme", "none, minimal, low, medium, high, xhigh, max"),
    ],
)
def test_a_reasoning_the_provider_does_not_accept_raises_naming_the_accepted_values(
    provider: str, reasoning: str, accepted: str
) -> None:
    settings = _settings(provider, reasoning=reasoning)

    with pytest.raises(ValueError, match=accepted):
        settings.resolve_reasoning(settings.resolve_model())


@pytest.mark.parametrize("reasoning", ["none", "low"])
def test_anthropic_passes_an_accepted_reasoning_through(reasoning: str) -> None:
    settings = _settings("anthropic", reasoning=reasoning)

    assert settings.resolve_reasoning("claude-haiku-5-5") == reasoning


def test_fireworks_passes_an_explicit_reasoning_through() -> None:
    settings = _settings("fireworks", reasoning="high")

    assert settings.resolve_reasoning(settings.resolve_model()) == "high"


def test_alibaba_takes_no_reasoning_setting() -> None:
    settings = _settings("alibaba", reasoning="low")

    with pytest.raises(ValueError, match="takes no reasoning setting"):
        settings.resolve_reasoning(settings.resolve_model())


def test_openrouter_passes_an_explicit_reasoning_through() -> None:
    settings = _settings("openrouter", reasoning="high")

    assert settings.resolve_reasoning(settings.resolve_model()) == "high"


@pytest.mark.parametrize(
    ("providers", "expected"),
    [
        ("", ()),
        ("sail-research", ("sail-research",)),
        (" sail-research , ,deepinfra/fp4", ("sail-research", "deepinfra/fp4")),
    ],
)
def test_openrouter_providers_resolve_to_the_listed_slugs(
    providers: str, expected: tuple[str, ...]
) -> None:
    settings = Settings(provider="openrouter", openrouter_providers=providers)

    assert settings.resolve_openrouter_providers() == expected


def test_the_openrouter_providers_are_read_from_the_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("MCP_AUDITOR_OPENROUTER_PROVIDERS", "sail-research")

    assert Settings().resolve_openrouter_providers() == ("sail-research",)
