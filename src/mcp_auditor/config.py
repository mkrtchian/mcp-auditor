from dotenv import load_dotenv
from pydantic_settings import BaseSettings

load_dotenv()


class Settings(BaseSettings):
    model_config = {"env_prefix": "MCP_AUDITOR_"}

    provider: str = "google"
    model: str = ""
    judge_model: str = ""
    langsmith_project: str = "mcp-auditor"

    def resolve_model(self) -> str:
        if self.model:
            return self.model
        return _default_model(self.provider)

    def resolve_judge_model(self) -> str:
        if self.judge_model:
            return self.judge_model
        return self.resolve_model()


def _default_model(provider: str) -> str:
    defaults = {
        "google": "gemini-3.1-flash-lite-preview",
        "anthropic": "claude-haiku-4-5-20251001",
    }
    if provider not in defaults:
        raise ValueError(f"Unknown provider: {provider!r}. Use 'google' or 'anthropic'.")
    return defaults[provider]


def load_settings() -> Settings:
    return Settings()
