import hashlib
from collections.abc import Sequence
from contextlib import AbstractContextManager
from pathlib import Path

import tests.unit.nuisance.admission.support.test_nuisance_admission_given as admission_given
from evals.cve.backends.lifecycle import BackendLifecycle, PerLaunchBackend
from evals.cve.detection.holdout_targets import HOLDOUT_TARGETS
from evals.cve.nuisance.admission.admission import AdmittedServer, BackendFixture, FlawRecord
from evals.cve.nuisance.admission.holdout_calibration_copies import copy_targets
from evals.cve.nuisance.admission.re_admission_dossier import (
    fix_check_modules,
    holdout_target_references,
    write_re_admission_dossier,
)
from evals.cve.nuisance.backend_registry import BACKENDS, RegisteredBackend
from evals.cve.planting_base import PlantingHost
from evals.honeypots import REPO_ROOT
from tests.unit.support.test_nuisance_committed_admission_given import (
    the_committed_admission,
    the_committed_walk_inputs,
)

A_DRAWN_TARGET = "CVE-2026-85787"
ITS_SIBLING = "CVE-2026-87911"
PER_LAUNCH_NETWORK_PREFIX = "fake-per-launch-net"


def a_per_launch_registry() -> dict[str, RegisteredBackend]:
    backend = PerLaunchBackend("fake_per_launch", _never_stood)
    registered = RegisteredBackend(backend, PER_LAUNCH_NETWORK_PREFIX, ("fake/engine:1.0",), (), ())
    return {backend.key: registered}


def a_server_on_a_per_launch_backend() -> AdmittedServer:
    backend = BackendFixture(
        provisioner="fake_per_launch", images=["fake/engine:1.0"], network=PER_LAUNCH_NETWORK_PREFIX
    )
    return admission_given.with_a_backend(admission_given.an_admitted_server(), backend)


def _never_stood(
    name: str, image: str, host: PlantingHost, server_launch: Sequence[str]
) -> AbstractContextManager[list[str]]:
    raise AssertionError("the dossier's documents never stand a backend")


def shared_backends() -> dict[str, RegisteredBackend]:
    return {
        key: entry
        for key, entry in BACKENDS.items()
        if isinstance(entry.lifecycle, BackendLifecycle)
    }


def the_copy_resolution() -> dict[str, str]:
    return copy_targets(
        [target.flaw_id for target in HOLDOUT_TARGETS], the_committed_walk_inputs().census.draw
    )


def a_committed_server_with_fix_checks() -> AdmittedServer:
    return next(server for server in the_committed_admission().servers if fix_check_modules(server))


def a_committed_server_with_a_backend() -> AdmittedServer:
    return next(
        server for server in the_committed_admission().servers if server.backend is not None
    )


def a_committed_server_with_a_holdout_copy() -> AdmittedServer:
    resolution = the_copy_resolution()
    return next(
        server
        for server in the_committed_admission().servers
        if holdout_target_references(server, resolution)
    )


def a_server_copying_a_drawn_target_and_its_sibling() -> AdmittedServer:
    base = admission_given.an_admitted_server()
    first = base.flaws[0]
    flaws = [_copying(first, A_DRAWN_TARGET), _copying(first, ITS_SIBLING)]
    return base.model_copy(update={"flaws": flaws})


def _copying(flaw: FlawRecord, flaw_id: str) -> FlawRecord:
    fix_check = flaw.fix_check.model_copy(update={"source": "detection_holdout_calibration"})
    return flaw.model_copy(update={"flaw": flaw_id, "fix_check": fix_check})


def a_written_dossier(tmp_path: Path, server_package: str) -> Path:
    out = tmp_path / "dossier"
    write_re_admission_dossier(
        the_committed_walk_inputs(), the_committed_admission(), server_package, out
    )
    return out


def copies_of_auditor_sources(out: Path) -> list[str]:
    """Each file under `out` whose path names mcp_auditor or whose bytes equal a file of src/.
    Empty files are left out: an empty `__init__.py` carries nothing of the auditor."""
    auditor = {_digest(path) for path in (REPO_ROOT / "src").rglob("*") if _is_non_empty_file(path)}
    return [
        str(path.relative_to(out))
        for path in sorted(out.rglob("*"))
        if path.is_file()
        and (
            "mcp_auditor" in str(path.relative_to(out))
            or (_is_non_empty_file(path) and _digest(path) in auditor)
        )
    ]


def _is_non_empty_file(path: Path) -> bool:
    return path.is_file() and path.stat().st_size > 0


def _digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()
