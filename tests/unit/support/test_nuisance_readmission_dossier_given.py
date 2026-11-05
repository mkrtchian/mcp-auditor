import hashlib
from pathlib import Path

from evals.honeypots import REPO_ROOT
from evals.nuisance_admission import AdmittedServer
from evals.nuisance_readmission_dossier import (
    fix_check_modules,
    holdout_references,
    write_readmission_dossier,
)
from tests.unit.support.test_nuisance_committed_admission_given import (
    the_committed_admission,
    the_committed_census,
)


def a_committed_server_with_fix_checks() -> AdmittedServer:
    return next(server for server in the_committed_admission().servers if fix_check_modules(server))


def a_committed_server_with_a_backend() -> AdmittedServer:
    return next(
        server for server in the_committed_admission().servers if server.backend is not None
    )


def a_committed_server_with_a_holdout_copy() -> AdmittedServer:
    return next(
        server for server in the_committed_admission().servers if holdout_references(server)
    )


def a_written_dossier(tmp_path: Path, server_package: str) -> Path:
    out = tmp_path / "dossier"
    write_readmission_dossier(
        the_committed_census(), the_committed_admission(), server_package, out
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
