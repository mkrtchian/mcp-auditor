import pytest

from mcp_auditor.config import Settings


def test_default_settings(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("MCP_AUDITOR_PROVIDER", raising=False)
    monkeypatch.delenv("MCP_AUDITOR_MODEL", raising=False)
    monkeypatch.delenv("MCP_AUDITOR_JUDGE_MODEL", raising=False)
    monkeypatch.delenv("MCP_AUDITOR_REASONING", raising=False)

    settings = Settings()

    assert settings.provider == "openai"
    assert settings.resolve_model() == "gpt-6-luna"
    assert settings.resolve_reasoning(settings.resolve_model()) == "none"


def test_anthropic_provider_defaults(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MCP_AUDITOR_PROVIDER", "anthropic")
    monkeypatch.delenv("MCP_AUDITOR_MODEL", raising=False)

    settings = Settings()

    assert settings.resolve_model() == "claude-haiku-4-5-20251001"


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
    for provider in ("google", "anthropic", "openai", "fireworks", "alibaba"):
        assert provider in str(error.value)


def _settings(provider: str, reasoning: str = "") -> Settings:
    return Settings(provider=provider, model="", judge_model="", reasoning=reasoning)


def test_google_resolves_minimal_reasoning_for_its_default_model() -> None:
    settings = _settings("google")

    model = settings.resolve_model()

    assert model == "gemini-3.5-flash-lite"
    assert settings.resolve_reasoning(model) == "minimal"


def test_anthropic_resolves_no_reasoning_for_its_default_model() -> None:
    settings = _settings("anthropic")

    model = settings.resolve_model()

    assert model == "claude-haiku-4-5-20251001"
    assert settings.resolve_reasoning(model) is None


def test_a_model_other_than_the_default_resolves_no_reasoning_when_unset() -> None:
    assert _settings("google").resolve_reasoning("gemini-3.1-pro-preview") is None


def test_a_model_other_than_the_default_takes_the_explicit_reasoning() -> None:
    settings = _settings("google", reasoning="high")

    assert settings.resolve_reasoning("gemini-3.1-pro-preview") == "high"


def test_an_accepted_explicit_reasoning_is_returned_as_set() -> None:
    settings = _settings("google", reasoning="low")

    assert settings.resolve_reasoning(settings.resolve_model()) == "low"


def test_a_reasoning_the_provider_does_not_accept_raises_naming_the_accepted_values() -> None:
    settings = _settings("google", reasoning="max")

    with pytest.raises(ValueError, match="minimal, low, medium, high"):
        settings.resolve_reasoning(settings.resolve_model())


def test_anthropic_with_any_reasoning_raises() -> None:
    settings = _settings("anthropic", reasoning="low")

    with pytest.raises(ValueError, match="takes no reasoning setting"):
        settings.resolve_reasoning(settings.resolve_model())


def test_openai_resolves_luna_at_reasoning_none_by_default() -> None:
    settings = _settings("openai")

    model = settings.resolve_model()

    assert model == "gpt-6-luna"
    assert settings.resolve_reasoning(model) == "none"


def test_fireworks_resolves_glm_at_medium_reasoning_by_default() -> None:
    settings = _settings("fireworks")

    model = settings.resolve_model()

    assert model == "accounts/fireworks/models/glm-5p3-flash"
    assert settings.resolve_reasoning(model) == "medium"


def test_fireworks_passes_an_explicit_reasoning_through() -> None:
    settings = _settings("fireworks", reasoning="high")

    assert settings.resolve_reasoning(settings.resolve_model()) == "high"


def test_openai_rejects_minimal_naming_its_accepted_values() -> None:
    settings = _settings("openai", reasoning="minimal")

    with pytest.raises(ValueError, match="none, low, medium, high, xhigh, max"):
        settings.resolve_reasoning(settings.resolve_model())


def test_alibaba_resolves_qwen_with_no_reasoning_setting() -> None:
    settings = _settings("alibaba")

    model = settings.resolve_model()

    assert model == "qwen3.8-flash"
    assert settings.resolve_reasoning(model) is None


def test_alibaba_takes_no_reasoning_setting() -> None:
    settings = _settings("alibaba", reasoning="low")

    with pytest.raises(ValueError, match="takes no reasoning setting"):
        settings.resolve_reasoning(settings.resolve_model())
