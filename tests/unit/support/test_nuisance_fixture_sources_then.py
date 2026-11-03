import re
from collections.abc import Sequence
from pathlib import Path

from evals.cve_images import dockerfile_instructions
from evals.cve_planting import PlantingHost
from evals.docker_paths import image_dockerfile
from evals.fixture_provenance import StandInRecord
from evals.nuisance_admission import AdmittedServer
from evals.nuisance_backends import BACKENDS
from evals.public_stand_ins import stand_in_files

REPOSITORY = Path(__file__).resolve().parents[3]

_HTTP_CHECKSUM = re.compile(r"--checksum=sha256:[0-9a-f]{64}")
_GIT_CHECKSUM = re.compile(r"--checksum=[0-9a-f]{40}")


def copies_nothing_unsourced(instructions: Sequence[str]) -> None:
    assert copy_problems(instructions) == []


def refuses_the_copy(instructions: Sequence[str]) -> None:
    assert copy_problems(instructions) != []


def copy_problems(instructions: Sequence[str]) -> list[str]:
    """A local COPY or ADD brings in content the fingerprint does not hash, and a remote ADD
    without a checksum in Docker's documented form brings in content nothing pins."""
    problems: list[str] = []
    for instruction in _joined(instructions):
        words = instruction.split()
        keyword = words[0].upper()
        flags = [word for word in words[1:] if word.startswith("--")]
        if keyword == "COPY" and not any(flag.startswith("--from=") for flag in flags):
            problems.append(f"local COPY: {instruction}")
        if keyword == "ADD":
            sources = [word for word in words[1:] if not word.startswith("--")][:-1]
            problems += [_add_problem(source, flags, instruction) for source in sources]
    return [problem for problem in problems if problem]


def _joined(instructions: Sequence[str]) -> list[str]:
    joined: list[str] = []
    pending = ""
    for line in instructions:
        if line.endswith("\\"):
            pending += f"{line[:-1]} "
            continue
        joined.append(pending + line)
        pending = ""
    return joined


def _add_problem(source: str, flags: Sequence[str], instruction: str) -> str:
    if _is_git(source):
        pinned = any(_GIT_CHECKSUM.fullmatch(flag) for flag in flags)
        return "" if pinned else f"git ADD without a full commit checksum: {instruction}"
    if source.startswith(("http://", "https://")):
        pinned = any(_HTTP_CHECKSUM.fullmatch(flag) for flag in flags)
        return "" if pinned else f"HTTP ADD without a sha256 checksum: {instruction}"
    return f"local ADD: {instruction}"


def _is_git(source: str) -> bool:
    return source.startswith(("git@", "git://")) or source.split("#")[0].endswith(".git")


def backend_served(server: AdmittedServer) -> tuple[Path, ...]:
    return () if server.backend is None else BACKENDS[server.backend.provisioner].served


def every_seed_pin_is_fingerprinted(server: AdmittedServer) -> None:
    covered = "\n".join(
        [
            *dockerfile_instructions(image_dockerfile(server.service)),
            *(path.read_text() for path in backend_served(server)),
        ]
    )
    pins = [seed.pin for seed in server.seeds or [] if seed.pin is not None]

    assert [pin for pin in pins if pin not in covered] == []


def every_stand_in_is_a_fingerprinted_file(server: AdmittedServer) -> None:
    fixture_files = (
        image_dockerfile(server.service),
        *backend_served(server),
        *host_stand_in_files(server.host),
    )
    covered = {path.resolve() for path in fixture_files}
    for stand_in in server.stand_ins or []:
        assert stand_in_paths_outside(stand_in, covered) == []
        assert requests_missing_from_the_file(stand_in) == []


def host_stand_in_files(host: PlantingHost) -> list[Path]:
    """The stand-in files cve_baseline.planting_host_parts hashes for the host."""
    loaded = [stand_in_files(name) for name in host.public_names.stand_ins]
    return [
        path
        for files in loaded
        for path in (files.capture, files.certificate, files.key, files.authority)
    ]


def stand_in_paths_outside(stand_in: StandInRecord, covered: set[Path]) -> list[str]:
    recorded = [stand_in.file] if stand_in.capture is None else [stand_in.file, stand_in.capture]
    return [path for path in recorded if (REPOSITORY / path).resolve() not in covered]


def requests_missing_from_the_file(stand_in: StandInRecord) -> list[str]:
    text = (REPOSITORY / stand_in.file).read_text()
    return [output.request for output in stand_in.outputs if output.request not in text]
