from pydantic import BaseModel

from mcp_auditor.config import Settings


class ModelConditions(BaseModel):
    """The provider, models and reasoning levels a run resolves from its settings."""

    provider: str
    model: str
    judge_model: str
    reasoning: str | None
    judge_reasoning: str | None

    @classmethod
    def of(cls, settings: Settings) -> "ModelConditions":
        """Raises ValueError on a reasoning the provider does not accept."""
        model = settings.resolve_model()
        judge_model = settings.resolve_judge_model()
        return cls(
            provider=settings.provider,
            model=model,
            judge_model=judge_model,
            reasoning=settings.resolve_reasoning(model),
            judge_reasoning=settings.resolve_reasoning(judge_model),
        )
