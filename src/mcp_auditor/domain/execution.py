from enum import StrEnum

from pydantic import BaseModel


class ExecutionRegime(StrEnum):
    CONFINED = "confined"
    DECLARED_CONTAINER = "declared_container"
    UNCONFINED = "unconfined"


class ExecutionRecord(BaseModel):
    regime: ExecutionRegime
    image: str | None = None
    image_digest: str | None = None
    writable_paths: list[str] | None = None
    read_only_paths: list[str] | None = None
    oom_killed: bool | None = None
    """Read with the regime: under `confined`, true when any container of the audit, one per
    launch of the server, was killed on memory, and `None` only when no container's kill state
    could be read. Under the other regimes it is always `None`, there being no container of the
    auditor's."""
    redacted_variables: list[str] | None = None
    plain_variables: dict[str, str] | None = None
