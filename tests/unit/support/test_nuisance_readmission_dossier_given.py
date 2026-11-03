import hashlib
from functools import cache
from pathlib import Path

from evals.holdout_census import load_census
from evals.nuisance_admission import (
    ADMISSION_PATH,
    AdmittedServer,
    NuisanceAdmission,
    load_admission,
)
from evals.nuisance_commands import CENSUS_PATH, WALK_RECORD_PATH
from evals.nuisance_readmission_dossier import write_readmission_dossier
from evals.nuisance_walk_record import NuisanceCensus, load_walk_record

REPO_ROOT = Path(__file__).resolve().parents[3]

PRAISONAI = "PyPI:praisonai"
APIFY = "npm:@apify/actors-mcp-server"
NEO4J = "PyPI:mcp-neo4j-cypher"
MYSQL = "PyPI:awslabs-mysql-mcp-server"


@cache
def the_committed_census() -> NuisanceCensus:
    return load_walk_record(WALK_RECORD_PATH, load_census(CENSUS_PATH))


@cache
def the_committed_admission() -> NuisanceAdmission:
    return load_admission(ADMISSION_PATH, the_committed_census())


def the_committed_server(server_package: str) -> AdmittedServer:
    servers = the_committed_admission().servers
    return next(server for server in servers if server.server_package == server_package)


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
