from pathlib import Path

from evals.cve.docker_paths import image_dockerfile
from evals.cve.fixture_sources import (
    unfingerprinted_pins,
    unfingerprinted_stand_in_files,
    unheld_requests,
    unserved_captures,
    unsourced_copies,
)
from evals.cve.images import dockerfile_instructions
from evals.cve.nuisance.admission import AdmittedServer
from evals.cve.nuisance.fingerprint import fingerprinted_files
from evals.honeypots import REPO_ROOT

_STAND_IN_DOCKERFILE = image_dockerfile("stand-in")


def every_dockerfile_copies_nothing_unsourced(server: AdmittedServer) -> None:
    problems = {
        dockerfile.name: unsourced_copies(dockerfile_instructions(dockerfile))
        for dockerfile in _dockerfiles(fingerprinted_files(server))
    }

    assert {name: found for name, found in problems.items() if found} == {}


def every_seed_pin_is_fingerprinted(server: AdmittedServer) -> None:
    covered = "\n".join(_fingerprinted_text(path) for path in fingerprinted_files(server))

    assert unfingerprinted_pins(server.seeds or [], covered) == []


def every_stand_in_is_a_fingerprinted_file_holding_its_requests(server: AdmittedServer) -> None:
    covered = fingerprinted_files(server)
    for stand_in in server.stand_ins or []:
        assert unfingerprinted_stand_in_files(stand_in, covered, REPO_ROOT) == []
        assert unheld_requests(stand_in, REPO_ROOT) == []
        assert unserved_captures(stand_in, _STAND_IN_DOCKERFILE, REPO_ROOT) == []


def _dockerfiles(paths: list[Path]) -> list[Path]:
    return [path for path in paths if path.name.startswith("Dockerfile.")]


def _fingerprinted_text(path: Path) -> str:
    if path.name.startswith("Dockerfile."):
        return "\n".join(dockerfile_instructions(path))
    return path.read_text()
