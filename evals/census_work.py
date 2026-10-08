"""Schemas of the census work directory, the files the census agents write.

Each file is JSONL, one record per line, read with `read_jsonl` so that an agent's
malformed line is refused with its file and line number.
"""

from datetime import date
from enum import StrEnum
from pathlib import Path
from typing import Literal, Self

from pydantic import BaseModel, ValidationError, model_validator

from evals.census_classification import SoftwareKind
from evals.census_prefilter import PrefilterTerm
from evals.census_sources import SourceName


class HitDecision(BaseModel):
    source: SourceName
    source_id: str
    decision: Literal["keep", "drop"]
    software_kind: SoftwareKind
    reason: str
    agent: str


class Gap(BaseModel):
    flaw_id: str
    source_id: str
    where_found: str
    agent: str


class RecallFinding(BaseModel):
    advisory_id: str | None
    link: str | None
    angle: str
    where_found: str

    @model_validator(mode="after")
    def _outside_the_sources_needs_a_link(self) -> Self:
        if self.advisory_id is None and not self.link:
            raise ValueError("a finding outside the three sources needs a link")
        return self


class VulnerableMcpEntry(BaseModel):
    cve_id: str
    listed: date
    found: bool


class Widening(BaseModel):
    term: PrefilterTerm
    hit_count: int


class Downloads(BaseModel):
    """The day each export was downloaded, `nvd` keyed by feed file name."""

    nvd: dict[str, date]
    osv: date


class AgentRole(StrEnum):
    COLLECTOR = "collector"
    RECALL = "recall"
    VULNERABLEMCP = "vulnerablemcp"
    CLASSIFIER = "classifier"


class AgentRecord(BaseModel):
    role: AgentRole
    scope: str
    model: str


def read_jsonl[Record: BaseModel](path: Path, schema: type[Record]) -> list[Record]:
    records: list[Record] = []
    for number, line in enumerate(path.read_text().splitlines(), start=1):
        if not line.strip():
            continue
        try:
            records.append(schema.model_validate_json(line))
        except ValidationError as error:
            raise ValueError(f"{path}, line {number}: {error}") from error
    return records
