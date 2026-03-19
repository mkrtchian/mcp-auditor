import pytest

from mcp_auditor.config import Settings


def test_default_settings(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("MCP_AUDITOR_PROVIDER", raising=False)
    monkeypatch.delenv("MCP_AUDITOR_MODEL", raising=False)
    monkeypatch.delenv("MCP_AUDITOR_JUDGE_MODEL", raising=False)

    settings = Settings()

    assert settings.provider == "google"
    assert settings.resolve_model() == "gemini-3.1-flash-lite-preview"


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


def test_unknown_provider(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MCP_AUDITOR_PROVIDER", "openai")
    monkeypatch.delenv("MCP_AUDITOR_MODEL", raising=False)

    settings = Settings()

    with pytest.raises(ValueError, match="Unknown provider"):
        settings.resolve_model()
