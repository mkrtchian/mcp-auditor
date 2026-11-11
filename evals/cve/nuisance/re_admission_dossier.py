"""Assemble, outside the repository, the re-admission dossier for one admitted server.

The first-admission dossier (`dossier.write_dossier`, which already carries the rule, the benign
probe, the capture tool and the reference of each holdout target among the server's flaws) plus
what the two blind agents need to fill the fields nuisance suite rule v3 and v4 add: the server's
committed record, the Dockerfiles of its run, its fix checks, its holdout targets and its backend
under `evals/docker/`, the server's fix-check modules and backend lifecycle with their import
closure, and the confinement stated for this server's launch.

This module imports `holdout_targets`, `fixtures` and `backend_registry`, none of them clean: only
the files it writes must be.
"""

import importlib
import pkgutil
import shutil
from collections.abc import Mapping
from pathlib import Path

from evals.cve import dossier_closure
from evals.cve.detection.holdout_targets import HOLDOUT_TARGETS
from evals.cve.detection.targets import Target
from evals.cve.kit.fix_check import FixCheckFixture
from evals.cve.nuisance import fix_checks, re_admission_docs
from evals.cve.nuisance.backend_registry import BACKENDS
from evals.cve.nuisance.dossier import write_dossier
from evals.cve.nuisance.fixtures import FIX_CHECK_FIXTURES
from evals.cve.nuisance.holdout_calibration_copies import copy_targets
from evals.cve.nuisance.holdout_target_reference import holdout_targets_among
from evals.cve.nuisance.walk_record import WalkInputs
from evals.cve_planting_base import SENTINEL_SERVICE, STAND_IN_SERVICE
from evals.docker_paths import image_dockerfile
from evals.eval_session import Refused
from evals.nuisance_admission import AdmittedServer, NuisanceAdmission


def write_re_admission_dossier(
    walk_inputs: WalkInputs, admission: NuisanceAdmission, server_package: str, out: Path
) -> None:
    server = _admitted_server(admission, server_package)
    resolution = copy_targets(
        [target.flaw_id for target in HOLDOUT_TARGETS], walk_inputs.census.draw
    )
    dockerfiles = re_admission_dockerfiles(server, resolution)
    closure = dossier_closure.import_closure(closure_roots(server))
    write_dossier(walk_inputs, server_package, out)
    (out / "admission_record.json").write_text(server.model_dump_json(indent=2))
    _copy_dockerfiles(out, [*dockerfiles, SENTINEL_SERVICE, STAND_IN_SERVICE])
    dossier_closure.copy_closure(out, closure)
    (out / "confinement.md").write_text(re_admission_docs.confinement_text(server))
    with (out / "README.md").open("a") as readme:
        readme.write(re_admission_docs.re_admission_readme(server, fix_check_modules(server)))


def _admitted_server(admission: NuisanceAdmission, server_package: str) -> AdmittedServer:
    for server in admission.servers:
        if server.server_package == server_package:
            return server
    raise Refused(
        f"Refused: the admission holds no server {server_package}.",
        ["A re-admission dossier is written for a server the committed admission holds."],
    )


def re_admission_dockerfiles(server: AdmittedServer, resolution: Mapping[str, str]) -> list[str]:
    services = [server.service]
    for fixture in _fix_check_fixtures(server):
        services += [fixture.vulnerable_service, fixture.patched_service]
        if fixture.server_patched_service is not None:
            services.append(fixture.server_patched_service)
    for holdout in _detection_holdout_targets(server, resolution):
        services += [*holdout.images, holdout.patched_image]
    if server.backend is not None:
        services += BACKENDS[server.backend.provisioner].built_services
    shared = {SENTINEL_SERVICE, STAND_IN_SERVICE}
    kept = [service for service in dict.fromkeys(services) if service not in shared]
    missing = [service for service in kept if not image_dockerfile(service).is_file()]
    if missing:
        raise Refused(
            f"Refused: {server.server_package} names a service with no Dockerfile.",
            [f"no {image_dockerfile(service)}" for service in missing],
        )
    return kept


def _detection_holdout_targets(
    server: AdmittedServer, resolution: Mapping[str, str]
) -> list[Target]:
    return [
        *holdout_target_references(server, resolution),
        *holdout_targets_among(f.flaw for f in server.flaws),
    ]


def _fix_check_fixtures(server: AdmittedServer) -> list[FixCheckFixture]:
    flaws = {flaw.flaw for flaw in server.flaws}
    return [fixture for fixture in FIX_CHECK_FIXTURES if fixture.flaw in flaws]


def fix_check_modules(server: AdmittedServer) -> list[str]:
    flaws = {flaw.flaw for flaw in server.flaws}
    modules: list[str] = []
    for info in pkgutil.iter_modules(fix_checks.__path__):
        name = f"{fix_checks.__name__}.{info.name}"
        # A shared helper of the package (a builder two flaws use) defines no fixture.
        fixtures: tuple[FixCheckFixture, ...] = getattr(
            importlib.import_module(name), "FIXTURES", ()
        )
        if any(fixture.flaw in flaws for fixture in fixtures):
            modules.append(name)
    return modules


def closure_roots(server: AdmittedServer) -> list[str]:
    roots = [
        *fix_check_modules(server),
        "evals.cve.kit.benign_probe",
        "evals.cve.kit.backend_launch",
    ]
    if server.backend is not None:
        roots.append(f"evals.{server.backend.provisioner}_backend")
    return roots


def holdout_target_references(
    server: AdmittedServer, resolution: Mapping[str, str]
) -> list[Target]:
    by_identifier = {target.flaw_id: target for target in HOLDOUT_TARGETS}
    copied = [flaw.flaw for flaw in server.flaws if flaw.fix_check.source == "holdout_calibration"]
    unknown = [flaw for flaw in copied if flaw not in resolution]
    if unknown:
        raise Refused(
            f"Refused: {server.server_package} has a holdout calibration copy"
            " with no holdout target.",
            [f"no drawn holdout target carries {flaw}" for flaw in unknown],
        )
    drawn = dict.fromkeys(resolution[flaw] for flaw in copied)
    return [by_identifier[target] for target in drawn]


def _copy_dockerfiles(out: Path, services: list[str]) -> None:
    docker_out = out / "evals" / "docker"
    docker_out.mkdir(parents=True, exist_ok=True)
    for service in services:
        source = image_dockerfile(service)
        shutil.copyfile(source, docker_out / source.name)
