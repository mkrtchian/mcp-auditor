from enum import StrEnum

from pydantic import BaseModel


class ModelCallKind(StrEnum):
    TEST_GENERATION = "test_generation"
    JUDGMENT = "judgment"
    CONTEXT_EXTRACTION = "context_extraction"
    CHAIN_PLANNING = "chain_planning"
    CHAIN_STEP_OBSERVATION = "chain_step_observation"
    CHAIN_STEP_PLANNING = "chain_step_planning"
    CHAIN_JUDGMENT = "chain_judgment"


class MissedCallCause(StrEnum):
    PROVIDER_REFUSAL = "provider_refusal"
    UNREADABLE_ANSWER = "unreadable_answer"
    PROVIDER_THROTTLED = "provider_throttled"
    PROMPT_TOO_LONG = "prompt_too_long"


class MissedModelCall(BaseModel):
    tool_name: str
    kind: ModelCallKind
    cause: MissedCallCause
    detail: str
