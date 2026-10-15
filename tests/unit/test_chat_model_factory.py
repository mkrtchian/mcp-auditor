# pyright: reportArgumentType=false
import subprocess
import sys

import httpx
import pytest

from mcp_auditor.adapters.chat_model_factory import make_chat_model
from mcp_auditor.config import Settings


def _transport_of(chat_model: object) -> object:
    client_args: dict[str, object] = getattr(chat_model, "client_args", None) or {}
    return client_args.get("transport")


class TestMakeChatModel:
    def test_google_default_model_gets_minimal_thinking(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setenv("GOOGLE_API_KEY", "dummy")
        settings = Settings(provider="google", model="", judge_model="", reasoning="")

        chat_model = make_chat_model(settings, settings.resolve_model())

        assert getattr(chat_model, "model", None) == "gemini-3.5-flash-lite"
        assert getattr(chat_model, "thinking_level", None) == "minimal"
        assert isinstance(_transport_of(chat_model), httpx.AsyncHTTPTransport)

    def test_google_judge_override_gets_no_thinking_level(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setenv("GOOGLE_API_KEY", "dummy")
        settings = Settings(
            provider="google", model="", judge_model="gemini-3.1-pro-preview", reasoning=""
        )

        chat_model = make_chat_model(settings, settings.resolve_judge_model())

        assert getattr(chat_model, "model", None) == "gemini-3.1-pro-preview"
        assert getattr(chat_model, "thinking_level", "unset") is None
        assert isinstance(_transport_of(chat_model), httpx.AsyncHTTPTransport)

    def test_anthropic_builds_the_named_model(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setenv("ANTHROPIC_API_KEY", "dummy")
        settings = Settings(provider="anthropic", model="", judge_model="", reasoning="")

        chat_model = make_chat_model(settings, settings.resolve_model())

        assert getattr(chat_model, "model", None) == "claude-haiku-4-5-20251001"
        assert getattr(chat_model, "reasoning_effort", "unset") is None
        assert getattr(chat_model, "thinking", "unset") is None
        assert getattr(chat_model, "max_tokens", None) == 8192
        assert getattr(chat_model, "default_request_timeout", None) == 120

    def test_anthropic_at_reasoning_none_disables_thinking(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setenv("ANTHROPIC_API_KEY", "dummy")
        settings = Settings(
            provider="anthropic", model="claude-haiku-5-5", judge_model="", reasoning="none"
        )

        chat_model = make_chat_model(settings, settings.resolve_model())

        assert getattr(chat_model, "model", None) == "claude-haiku-5-5"
        assert getattr(chat_model, "thinking", None) == {"type": "disabled"}
        assert getattr(chat_model, "reasoning_effort", "unset") is None

    def test_anthropic_at_an_effort_thinks_adaptively(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setenv("ANTHROPIC_API_KEY", "dummy")
        settings = Settings(
            provider="anthropic", model="claude-haiku-5-5", judge_model="", reasoning="low"
        )

        chat_model = make_chat_model(settings, settings.resolve_model())

        assert getattr(chat_model, "reasoning_effort", None) == "low"
        assert getattr(chat_model, "thinking", None) == {"type": "adaptive"}

    @pytest.mark.parametrize("key", [None, ""])
    def test_anthropic_without_its_key_raises_naming_it(
        self, monkeypatch: pytest.MonkeyPatch, key: str | None
    ):
        if key is None:
            monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
        else:
            monkeypatch.setenv("ANTHROPIC_API_KEY", key)
        settings = Settings(provider="anthropic", model="", judge_model="", reasoning="")

        with pytest.raises(ValueError, match="ANTHROPIC_API_KEY"):
            make_chat_model(settings, settings.resolve_model())

    def test_openai_builds_luna_at_reasoning_none(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setenv("OPENAI_API_KEY", "dummy")
        settings = Settings(provider="openai", model="", judge_model="", reasoning="")

        chat_model = make_chat_model(settings, settings.resolve_model())

        assert getattr(chat_model, "model_name", None) == "gpt-6-luna"
        assert getattr(chat_model, "reasoning_effort", None) == "none"
        assert getattr(chat_model, "request_timeout", None) == 120
        assert getattr(chat_model, "max_tokens", None) == 8192

    def test_fireworks_builds_glm_at_medium_reasoning(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setenv("FIREWORKS_API_KEY", "dummy")
        settings = Settings(provider="fireworks", model="", judge_model="", reasoning="")

        chat_model = make_chat_model(settings, settings.resolve_model())

        assert getattr(chat_model, "model_name", None) == "accounts/fireworks/models/glm-5p3-flash"
        assert getattr(chat_model, "reasoning_effort", None) == "medium"
        assert getattr(chat_model, "request_timeout", None) == 120
        assert getattr(chat_model, "max_tokens", None) == 8192

    def test_fireworks_passes_an_explicit_reasoning(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setenv("FIREWORKS_API_KEY", "dummy")
        settings = Settings(provider="fireworks", model="", judge_model="", reasoning="high")

        chat_model = make_chat_model(settings, settings.resolve_model())

        assert getattr(chat_model, "reasoning_effort", None) == "high"

    def test_openai_without_its_key_raises_naming_it(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.delenv("OPENAI_API_KEY", raising=False)
        settings = Settings(provider="openai", model="", judge_model="", reasoning="")

        with pytest.raises(ValueError, match="OPENAI_API_KEY"):
            make_chat_model(settings, settings.resolve_model())

    def test_openai_with_an_empty_key_raises_naming_it(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setenv("OPENAI_API_KEY", "")
        settings = Settings(provider="openai", model="", judge_model="", reasoning="")

        with pytest.raises(ValueError, match="OPENAI_API_KEY"):
            make_chat_model(settings, settings.resolve_model())

    def test_alibaba_builds_qwen_on_chat_completions_with_thinking_off(
        self, monkeypatch: pytest.MonkeyPatch
    ):
        monkeypatch.setenv("DASHSCOPE_API_KEY", "dummy")
        settings = Settings(provider="alibaba", model="", judge_model="", reasoning="")

        chat_model = make_chat_model(settings, settings.resolve_model())

        assert getattr(chat_model, "model_name", None) == "qwen3.8-flash"
        assert str(getattr(chat_model, "openai_api_base", "")) == (
            "https://dashscope-intl.aliyuncs.com/compatible-mode/v1"
        )
        assert getattr(chat_model, "extra_body", None) == {"enable_thinking": False}
        assert not getattr(chat_model, "use_responses_api", True)
        assert getattr(chat_model, "request_timeout", None) == 120
        assert getattr(chat_model, "max_tokens", None) == 8192

    @pytest.mark.parametrize("key", [None, ""])
    def test_alibaba_without_its_key_raises_naming_it(
        self, monkeypatch: pytest.MonkeyPatch, key: str | None
    ):
        if key is None:
            monkeypatch.delenv("DASHSCOPE_API_KEY", raising=False)
        else:
            monkeypatch.setenv("DASHSCOPE_API_KEY", key)
        settings = Settings(provider="alibaba", model="", judge_model="", reasoning="")

        with pytest.raises(ValueError, match="DASHSCOPE_API_KEY"):
            make_chat_model(settings, settings.resolve_model())

    def test_openrouter_builds_glm_at_low_reasoning_on_open_routing(
        self, monkeypatch: pytest.MonkeyPatch
    ):
        monkeypatch.setenv("OPENROUTER_API_KEY", "dummy")
        settings = _openrouter_settings()

        chat_model = make_chat_model(settings, settings.resolve_model())

        assert getattr(chat_model, "model_name", None) == "z-ai/glm-5.3"
        assert str(getattr(chat_model, "openai_api_base", "")) == "https://openrouter.ai/api/v1"
        assert getattr(chat_model, "use_responses_api", None) is False
        assert getattr(chat_model, "max_tokens", None) == 8192
        assert getattr(chat_model, "request_timeout", None) == 120
        assert getattr(chat_model, "extra_body", None) == {
            "provider": {"require_parameters": True},
            "reasoning": {"effort": "low"},
        }

    def test_openrouter_pins_the_listed_hosts_without_fallback(
        self, monkeypatch: pytest.MonkeyPatch
    ):
        monkeypatch.setenv("OPENROUTER_API_KEY", "dummy")
        settings = _openrouter_settings(openrouter_hosts="sail-research")

        chat_model = make_chat_model(settings, settings.resolve_model())

        extra_body: dict[str, object] = getattr(chat_model, "extra_body", None) or {}
        assert extra_body["provider"] == {
            "require_parameters": True,
            "order": ["sail-research"],
            "allow_fallbacks": False,
        }

    def test_openrouter_model_override_sends_no_reasoning(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setenv("OPENROUTER_API_KEY", "dummy")
        settings = _openrouter_settings(model="z-ai/glm-5.3-flash")

        chat_model = make_chat_model(settings, settings.resolve_model())

        extra_body: dict[str, object] = getattr(chat_model, "extra_body", None) or {}
        assert "reasoning" not in extra_body

    @pytest.mark.parametrize("key", [None, ""])
    def test_openrouter_without_its_key_raises_naming_it(
        self, monkeypatch: pytest.MonkeyPatch, key: str | None
    ):
        if key is None:
            monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)
        else:
            monkeypatch.setenv("OPENROUTER_API_KEY", key)
        settings = _openrouter_settings()

        with pytest.raises(ValueError, match="OPENROUTER_API_KEY"):
            make_chat_model(settings, settings.resolve_model())


def _openrouter_settings(model: str = "", openrouter_hosts: str = "") -> Settings:
    return Settings(
        provider="openrouter",
        model=model,
        judge_model="",
        reasoning="",
        openrouter_hosts=openrouter_hosts,
    )


_PROVIDER_SDKS = (
    "langchain_anthropic",
    "langchain_fireworks",
    "langchain_google_genai",
    "langchain_openai",
)
_PRINT_THE_SDKS_THE_CLI_LOADS = (
    f"import sys, mcp_auditor.cli; print(*(m for m in {_PROVIDER_SDKS!r} if m in sys.modules))"
)


def test_starting_the_cli_loads_no_provider_sdk():
    loaded = subprocess.run(
        [sys.executable, "-c", _PRINT_THE_SDKS_THE_CLI_LOADS],
        capture_output=True,
        text=True,
        check=True,
    ).stdout.split()

    assert loaded == []
