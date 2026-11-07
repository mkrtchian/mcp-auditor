"""Assemble, outside the repository, the re-admission dossier for one admitted server.

The first-admission dossier (`nuisance_dossier.write_dossier`, which already carries the rule,
the benign probe, the capture tool and the holdout reference of each holdout target among the
server's flaws) plus what the two blind agents need to fill the fields rules v3 and v4 add: the
server's committed record, the run's, fix-check, holdout-twin and backend Dockerfiles under
`evals/docker/`, the server's fix-check modules and backend lifecycle with their import closure,
and the confinement stated for this server's launch.

This module imports `holdout_targets`, `nuisance_fixtures` and `nuisance_backends`, none of them
clean: only the files it writes must be.
"""

import importlib
import pkgutil
import shutil
from pathlib import Path

from evals import dossier_closure, nuisance_fix_checks, nuisance_readmission_docs
from evals.cve_planting_base import SENTINEL_SERVICE, STAND_IN_SERVICE
from evals.cve_targets import CVETarget
from evals.docker_paths import image_dockerfile
from evals.eval_session import Refused
from evals.holdout_kit.fix_check import FixCheckTarget
from evals.holdout_targets import HOLDOUT_TARGETS
from evals.nuisance_admission import AdmittedServer, NuisanceAdmission
from evals.nuisance_backends import BACKENDS
from evals.nuisance_dossier import write_dossier
from evals.nuisance_fixtures import FIX_CHECK_TARGETS
from evals.nuisance_walk_record import NuisanceCensus


def write_readmission_dossier(
    nuisance_census: NuisanceCensus, admission: NuisanceAdmission, server_package: str, out: Path
) -> None:
    server = _admitted_server(admission, server_package)
    dockerfiles = readmission_dockerfiles(server)
    closure = dossier_closure.import_closure(closure_roots(server))
    write_dossier(nuisance_census, server_package, out)
    (out / "admission_record.json").write_text(server.model_dump_json(indent=2))
    _copy_dockerfiles(out, [*dockerfiles, SENTINEL_SERVICE, STAND_IN_SERVICE])
    dossier_closure.copy_closure(out, closure)
    (out / "confinement.md").write_text(nuisance_readmission_docs.confinement_text(server))
    with (out / "README.md").open("a") as readme:
        readme.write(
            nuisance_readmission_docs.readmission_readme(server, fix_check_modules(server))
        )


def _admitted_server(admission: NuisanceAdmission, server_package: str) -> AdmittedServer:
    for server in admission.servers:
        if server.server_package == server_package:
            return server
    raise Refused(
        f"Refused: the admission holds no server {server_package}.",
        ["A re-admission dossier is written for a server the committed admission holds."],
    )


def readmission_dockerfiles(server: AdmittedServer) -> list[str]:
    services = [server.service]
    for target in _fix_check_targets(server):
        services += [target.vulnerable_service, target.patched_service]
        if target.server_patched_service is not None:
            services.append(target.server_patched_service)
    for holdout in holdout_references(server):
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


def _fix_check_targets(server: AdmittedServer) -> list[FixCheckTarget]:
    flaws = {flaw.flaw for flaw in server.flaws}
    return [target for target in FIX_CHECK_TARGETS if target.flaw in flaws]


def fix_check_modules(server: AdmittedServer) -> list[str]:
    flaws = {flaw.flaw for flaw in server.flaws}
    modules: list[str] = []
    for info in pkgutil.iter_modules(nuisance_fix_checks.__path__):
        name = f"{nuisance_fix_checks.__name__}.{info.name}"
        targets: tuple[FixCheckTarget, ...] = importlib.import_module(name).TARGETS
        if any(target.flaw in flaws for target in targets):
            modules.append(name)
    return modules


def closure_roots(server: AdmittedServer) -> list[str]:
    roots = [
        *fix_check_modules(server),
        "evals.holdout_kit.benign_probe",
        "evals.holdout_kit.kit_backend_launch",
    ]
    if server.backend is not None:
        roots.append(f"evals.{server.backend.provisioner}_backend")
    return roots


def holdout_references(server: AdmittedServer) -> list[CVETarget]:
    by_identifier = {target.cve_id: target for target in HOLDOUT_TARGETS}
    calibrated = [
        flaw.flaw for flaw in server.flaws if flaw.fix_check.source == "holdout_calibration"
    ]
    unknown = [flaw for flaw in calibrated if flaw not in by_identifier]
    if unknown:
        raise Refused(
            f"Refused: {server.server_package} has a holdout-calibration flaw with no target.",
            [f"no HOLDOUT_TARGETS entry carries {flaw}" for flaw in unknown],
        )
    return [by_identifier[flaw] for flaw in calibrated]


def _copy_dockerfiles(out: Path, services: list[str]) -> None:
    docker_out = out / "evals" / "docker"
    docker_out.mkdir(parents=True, exist_ok=True)
    for service in services:
        source = image_dockerfile(service)
        shutil.copyfile(source, docker_out / source.name)
