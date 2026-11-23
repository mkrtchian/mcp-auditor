"""The admission file of the nuisance suite: the servers the maintainer admits, one file of
its own (`evals/nuisance_admission.json`), distinct from the census.

The schema is filled by the two blind admission agents and the maintainer who settles their
disagreements, on the model of the draw record of `evals/cve/detection/draw_record.py`. `exits`
records each server the nuisance walk lists and the admission leaves out, with its reason.
`admission_load.py` holds the load validation. A field defaulting to `None` is one nuisance suite
rule v3 or v4 added and not yet recorded, which `unrecorded.py` refuses at run, except `backend`,
which is `None` on a server with no backend.
"""

from typing import Any, Literal

from pydantic import BaseModel

from evals.cve.census.work import AgentRecord
from evals.cve.detection.draw_record import LaunchOption
from evals.cve.fixture_provenance import SoftwareRelease, StandInRecord
from evals.cve.grammar import FlawClass
from evals.cve.nuisance.admission.admission_records import RealSoftwareRecord, SeedRecord
from evals.cve.nuisance.exits import ExitReason, RecordedExit
from evals.cve.planting_base import PlantingHost
from evals.repository import REPO_ROOT

ADMISSION_PATH = REPO_ROOT / "evals" / "nuisance_admission.json"


class ToolRecord(BaseModel):
    vulnerable_name: str | None
    patched_name: str | None
    status: Literal["unchanged", "renamed", "removed"]
    real_software: RealSoftwareRecord | None = None
    # The counter reads it, falling back to FlawRecord.declared_function_is_effect when None.
    declared_function_is_effect: bool | None = None


class ToolCall(BaseModel):
    tool: str
    arguments: dict[str, Any]


class BenignCall(ToolCall):
    expect: str | None = None  # a substring the response text must contain
    before: list[ToolCall] | None = None  # prerequisite calls, each must not error


class FixCheckRecord(BaseModel):
    source: Literal["fix_check", "detection_holdout_calibration"]
    witness: str
    exploit_calls: list[str]
    vulnerable_surfaces: bool
    patched_surfaces: bool
    server_patched_surfaces: bool | None
    patched_benign_errored: bool
    relies_on_relaying_stand_in: bool | None = None
    # The holdout target's fixture fingerprint a detection_holdout_calibration record was copied at.
    holdout_fingerprint: str | None = None

    @property
    def is_holdout_calibration_copy(self) -> bool:
        return self.source == "detection_holdout_calibration"


class FlawRecord(BaseModel):
    flaw: str
    tools: list[ToolRecord]
    effect_class: FlawClass | None
    patched_version: str | None
    patched_source: Literal["advisory", "fix_commit", "none"]
    launch_option: LaunchOption | None
    benign_calls: list[BenignCall]
    # "none": no tool of the flaw needs a backend.
    # "fixture": a tool needs a backend the fixture provides (the server's own backend fixture
    # or one baked into its image).
    # "external": a tool needs a backend the fixture cannot provide, which drops the tool.
    backend_need: Literal["none", "fixture", "external"]
    declared_function_is_effect: bool
    fix_check: FixCheckRecord


class FieldAgreement(BaseModel):
    flaw: str | None
    field: str
    agreed: bool


class AdmissionSettlement(BaseModel):
    server_package: str
    flaw: str | None
    field: str
    value: str
    reason: str


class BackendFixture(BaseModel):
    provisioner: str
    images: list[str]
    network: str


class AdmittedServer(BaseModel):
    server_package: str
    reaching_flaw: str
    flaws: list[FlawRecord]
    runs_over_stdio: bool
    runs_under_docker: bool
    host: PlantingHost
    launch: list[str]
    service: str
    backend: BackendFixture | None = None
    agents: list[AgentRecord]
    agreement: list[FieldAgreement]
    settlements: list[AdmissionSettlement]
    patched_version: str
    stand_ins: list[StandInRecord] | None = None
    seeds: list[SeedRecord] | None = None
    software_releases: list[SoftwareRelease] | None = None

    @property
    def standing_exit(self) -> ExitReason | None:
        if not self.runs_over_stdio:
            return ExitReason.NOT_OVER_STDIO
        if not self.runs_under_docker:
            return ExitReason.NOT_UNDER_DOCKER
        return None


class NuisanceAdmission(BaseModel):
    rule_commit: str
    grammar_fingerprint: str
    servers: list[AdmittedServer]
    exits: list[RecordedExit]
