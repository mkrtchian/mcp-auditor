"""The admission file of the nuisance suite: the servers the maintainer admits, one file of
its own (`evals/nuisance_admission.json`), distinct from the holdout census.

The schema is filled by the two blind admission agents and the maintainer who settles their
disagreements, on the model of the draw record of `evals/census_draw.py`. Every list is empty
until the admission session. `admission_problems` holds the load validation, raised joined by
`load_admission`, so a crafted admission can be checked without a file. The file is absent
until the session, and `load_admission` says so.
"""

from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel

from evals import cve_baseline, nuisance_images, nuisance_walk
from evals.census_draw import LaunchOption
from evals.census_work import AgentRecord
from evals.cve_grammar import MechanismClass
from evals.holdout_census import HoldoutCensus
from evals.honeypots import REPO_ROOT
from evals.nuisance_counting import counted_flaws, counted_tools

ADMISSION_PATH = REPO_ROOT / "evals" / "nuisance_admission.json"


class ToolRecord(BaseModel):
    vulnerable_name: str | None
    patched_name: str | None
    status: Literal["unchanged", "renamed", "removed"]


class BenignCall(BaseModel):
    tool: str
    arguments: dict[str, Any]


class FixCheckRecord(BaseModel):
    source: Literal["fix_check", "holdout_calibration"]
    witness: str
    exploit_calls: list[str]
    vulnerable_surfaces: bool
    patched_surfaces: bool
    server_patched_surfaces: bool | None
    patched_benign_errored: bool


class FlawRecord(BaseModel):
    flaw: str
    tools: list[ToolRecord]
    effect_class: MechanismClass | None
    patched_version: str | None
    patched_source: Literal["advisory", "fix_commit", "none"]
    launch_option: LaunchOption | None
    benign_calls: list[BenignCall]
    needs_backend: bool
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


class AdmittedServer(BaseModel):
    server_package: str
    reaching_flaw: str
    flaws: list[FlawRecord]
    runs_over_stdio: bool
    runs_in_container: bool
    launch: list[str]
    service: str
    agents: list[AgentRecord]
    agreement: list[FieldAgreement]
    settlements: list[AdmissionSettlement]
    patched_version: str


class NuisanceAdmission(BaseModel):
    rule_commit: str
    grammar_fingerprint: str
    servers: list[AdmittedServer]


def load_admission(path: Path, census: HoldoutCensus) -> NuisanceAdmission:
    if not path.exists():
        raise FileNotFoundError(
            f"no admission at {path}: the admission session has not been committed"
        )
    admission = NuisanceAdmission.model_validate_json(path.read_text())
    problems = admission_problems(admission, census, cve_baseline.grammar_fingerprint())
    if problems:
        raise ValueError(f"invalid nuisance admission {path}: {'; '.join(problems)}")
    return admission


def admission_problems(
    admission: NuisanceAdmission, census: HoldoutCensus, grammar_fingerprint: str
) -> list[str]:
    problems = _fingerprint_problems(admission, grammar_fingerprint)
    problems += nuisance_images.namespace_problems(admission)
    for server in admission.servers:
        problems += _unsettled_disagreements(server)
        problems += _foreign_flaws(server, census)
        problems += _counted_tool_problems(server)
        problems += _patched_version_problems(server)
    return problems


def _fingerprint_problems(admission: NuisanceAdmission, grammar_fingerprint: str) -> list[str]:
    if admission.grammar_fingerprint == grammar_fingerprint:
        return []
    return [
        f"grammar fingerprint {admission.grammar_fingerprint} is not the current "
        f"{grammar_fingerprint}"
    ]


def _unsettled_disagreements(server: AdmittedServer) -> list[str]:
    return [
        f"{server.server_package}: disagreement on {agreement.field} "
        f"(flaw {agreement.flaw}) has no settlement"
        for agreement in server.agreement
        if not agreement.agreed and not _is_settled(server, agreement)
    ]


def _is_settled(server: AdmittedServer, agreement: FieldAgreement) -> bool:
    return any(
        settlement.server_package == server.server_package
        and settlement.flaw == agreement.flaw
        and settlement.field == agreement.field
        for settlement in server.settlements
    )


def _foreign_flaws(server: AdmittedServer, census: HoldoutCensus) -> list[str]:
    census_flaws = set(nuisance_walk.census_flaws_of(server.server_package, census))
    return [
        f"{server.server_package}: flaw {flaw.flaw} is not a census flaw of the server"
        for flaw in server.flaws
        if flaw.flaw not in census_flaws
    ]


def _counted_tool_problems(server: AdmittedServer) -> list[str]:
    if counted_tools(server):
        return []
    return [f"{server.server_package}: no counted tool"]


def _patched_version_problems(server: AdmittedServer) -> list[str]:
    counted = counted_flaws(server)
    versions = {flaw.patched_version for flaw in counted}
    problems: list[str] = []
    if server.patched_version not in versions:
        problems.append(
            f"{server.server_package}: patched version {server.patched_version} "
            f"is not a counted flaw's patched version"
        )
    for flaw in counted:
        same = flaw.patched_version == server.patched_version
        unset = flaw.fix_check.server_patched_surfaces is None
        if same and not unset:
            problems.append(
                f"{server.server_package}: flaw {flaw.flaw} sets server_patched_surfaces "
                f"on the server's own patched version"
            )
        if not same and unset:
            problems.append(
                f"{server.server_package}: flaw {flaw.flaw} leaves server_patched_surfaces "
                f"unset on a differing patched version"
            )
    return problems
