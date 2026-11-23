from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

from evals.cve.detection import baseline as detection_baseline
from evals.cve.nuisance import backend_registry
from evals.cve.nuisance import images as nuisance_images
from evals.cve.nuisance.admission import walk as nuisance_walk
from evals.cve.nuisance.admission.admission import (
    AdmittedServer,
    FieldAgreement,
    FlawRecord,
    NuisanceAdmission,
    ToolRecord,
)
from evals.cve.nuisance.admission.admission_records import record_problems
from evals.cve.nuisance.admission.admission_walk import exit_problems, walk_problems
from evals.cve.nuisance.admission.walk_record import WalkInputs
from evals.cve.nuisance.counting import counted_flaws, counted_tools


def load_admission(path: Path, walk_inputs: WalkInputs) -> NuisanceAdmission:
    if not path.exists():
        raise FileNotFoundError(
            f"no admission at {path}: the admission session has not been committed"
        )
    admission = NuisanceAdmission.model_validate_json(path.read_text())
    references = AdmissionReferences(
        walk_inputs, detection_baseline.grammar_fingerprint(), backend_registry.BACKENDS
    )
    problems = admission_problems(admission, references)
    if problems:
        raise ValueError(f"invalid nuisance admission {path}: {'; '.join(problems)}")
    return admission


@dataclass(frozen=True)
class AdmissionReferences:
    """What the admission's names and fingerprint are checked against."""

    walk_inputs: WalkInputs
    grammar_fingerprint: str
    backends: Mapping[str, backend_registry.RegisteredBackend]


def admission_problems(admission: NuisanceAdmission, references: AdmissionReferences) -> list[str]:
    walk_inputs = references.walk_inputs
    problems = _fingerprint_problems(admission, references.grammar_fingerprint)
    problems += nuisance_images.namespace_problems(admission)
    for server in admission.servers:
        problems += _unsettled_disagreements(server)
        problems += _foreign_flaws(server, walk_inputs)
        problems += _tool_record_problems(server)
        problems += _counted_tool_problems(server)
        problems += _benign_call_problems(server)
        problems += _patched_version_problems(server)
        problems += _network_problems(server)
        problems += backend_registry.backend_problems(server, references.backends)
        problems += record_problems(server)
    return problems + walk_problems(admission, walk_inputs) + exit_problems(admission, walk_inputs)


def _fingerprint_problems(admission: NuisanceAdmission, grammar_fingerprint: str) -> list[str]:
    if admission.grammar_fingerprint == grammar_fingerprint:
        return []
    return [
        f"grammar fingerprint {admission.grammar_fingerprint} is not the current "
        f"{grammar_fingerprint}"
    ]


def _network_problems(server: AdmittedServer) -> list[str]:
    problems: list[str] = []
    if server.host.has_network and server.backend is None:
        problems.append(
            f"{server.server_package}: has_network without a backend: "
            "a server with no backend runs with no network"
        )
    names = server.host.public_names
    if names.trust and not names.stand_ins:
        # The launch plants only for a stand-in, so a trust setting alone would be ignored.
        problems.append(f"{server.server_package}: a trust setting with no stand-in")
    return problems


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


def _foreign_flaws(server: AdmittedServer, walk_inputs: WalkInputs) -> list[str]:
    census_flaws = set(nuisance_walk.census_flaws_of(server.server_package, walk_inputs))
    all_census_flaws = {flaw.identifier for flaw in walk_inputs.census.flaws}
    return [
        f"{server.server_package}: flaw {flaw.flaw} is not a census flaw of the server"
        for flaw in server.flaws
        if flaw.flaw not in census_flaws
        and not _settled_to_server(server, flaw.flaw, all_census_flaws)
    ]


def _settled_to_server(server: AdmittedServer, flaw: str, all_census_flaws: set[str]) -> bool:
    # A classifier may record a flaw under another spelling of the server (the ContextForge case),
    # so the maintainer unifies it with a server_package settlement naming this package.
    return flaw in all_census_flaws and any(
        settlement.server_package == server.server_package
        and settlement.flaw == flaw
        and settlement.field == "server_package"
        and settlement.value == server.server_package
        for settlement in server.settlements
    )


def _tool_record_problems(server: AdmittedServer) -> list[str]:
    problems: list[str] = []
    for flaw in server.flaws:
        for tool in flaw.tools:
            detail = _tool_record_defect(tool)
            if detail is not None:
                problems.append(f"{server.server_package}: flaw {flaw.flaw} {detail}")
    return problems


def _tool_record_defect(tool: ToolRecord) -> str | None:
    if tool.status == "removed":
        if tool.patched_name is not None:
            return f"removed tool {tool.vulnerable_name!r} keeps a patched name"
        return None
    if tool.vulnerable_name is None or tool.patched_name is None:
        return f"{tool.status} tool leaves a name unset"
    renamed = tool.vulnerable_name != tool.patched_name
    if tool.status == "renamed" and not renamed:
        return f"renamed tool {tool.patched_name!r} keeps the same name"
    if tool.status == "unchanged" and renamed:
        return f"unchanged tool renames {tool.vulnerable_name!r} to {tool.patched_name!r}"
    return None


def _counted_tool_problems(server: AdmittedServer) -> list[str]:
    if counted_tools(server):
        return []
    return [f"{server.server_package}: no counted tool"]


def _benign_call_problems(server: AdmittedServer) -> list[str]:
    counted = counted_tools(server)
    called = {call.tool for flaw in counted_flaws(server) for call in flaw.benign_calls}
    return [
        f"{server.server_package}: counted tool {name!r} has no benign call"
        for name in counted
        if name not in called
    ]


def _patched_version_problems(server: AdmittedServer) -> list[str]:
    counted = counted_flaws(server)
    return [
        *_version_of_no_counted_flaw(server, counted),
        *_server_patched_surfaces_problems(server, counted),
    ]


def _version_of_no_counted_flaw(server: AdmittedServer, counted: list[FlawRecord]) -> list[str]:
    if not counted:
        # The missing version has no counted flaw to pin it to: _counted_tool_problems already
        # names that, so a second problem here would only be noise.
        return []
    if server.patched_version in {flaw.patched_version for flaw in counted}:
        return []
    return [
        f"{server.server_package}: patched version {server.patched_version} "
        f"is not a counted flaw's patched version"
    ]


def _server_patched_surfaces_problems(
    server: AdmittedServer, counted: list[FlawRecord]
) -> list[str]:
    problems: list[str] = []
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
