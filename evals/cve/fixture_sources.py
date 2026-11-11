"""Problems with what a fixture brings in that its fingerprint does not hash.

Each function returns the offending items, empty when the fixture is sourced from fingerprinted
content only.
"""

import re
from collections.abc import Collection, Sequence
from pathlib import Path

from evals.cve.fixture_provenance import StandInRecord
from evals.cve.nuisance.admission_records import SeedRecord

_HTTP_CHECKSUM = re.compile(r"--checksum=sha256:[0-9a-f]{64}")
_GIT_CHECKSUM = re.compile(r"--checksum=[0-9a-f]{40}")
_PINNED_IMAGE = re.compile(r"[^@\s]+@sha256:[0-9a-f]{64}")


def unsourced_copies(instructions: Sequence[str]) -> list[str]:
    """A local COPY or ADD brings in content the fingerprint does not hash, a COPY from an image
    not pinned by digest content nothing pins, and a remote ADD without a checksum in Docker's
    documented form content nothing pins either."""
    problems: list[str] = []
    stages: set[str] = set()
    for instruction in _joined(instructions):
        words = instruction.split()
        keyword = words[0].upper()
        flags = [word for word in words[1:] if word.startswith("--")]
        if keyword == "FROM":
            stages |= _declared_stage(words)
        if keyword == "COPY":
            problems.append(_copy_problem(flags, stages, instruction))
        if keyword == "ADD":
            sources = [word for word in words[1:] if not word.startswith("--")][:-1]
            problems += [_add_problem(source, flags, instruction) for source in sources]
    return [problem for problem in problems if problem]


def _declared_stage(words: Sequence[str]) -> set[str]:
    operands = [word for word in words[1:] if not word.startswith("--")]
    if len(operands) == 3 and operands[1].upper() == "AS":
        return {operands[2].lower()}
    return set()


def _copy_problem(flags: Sequence[str], stages: Collection[str], instruction: str) -> str:
    sources = [flag.removeprefix("--from=") for flag in flags if flag.startswith("--from=")]
    if not sources:
        return f"local COPY: {instruction}"
    source = sources[0]
    if source.lower() in stages or _PINNED_IMAGE.fullmatch(source):
        return ""
    return f"COPY from neither an earlier stage nor an image pinned by digest: {instruction}"


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


def unfingerprinted_pins(seeds: Sequence[SeedRecord], covered_text: str) -> list[str]:
    pins = [seed.pin for seed in seeds if seed.pin is not None]
    return [pin for pin in pins if pin not in covered_text]


def unfingerprinted_stand_in_files(
    stand_in: StandInRecord, covered: Collection[Path], root: Path
) -> list[str]:
    """The stand-in's recorded files (its implementation and any capture), relative to `root`,
    that are not among the covered files."""
    resolved = {path.resolve() for path in covered}
    recorded = [stand_in.file] if stand_in.capture is None else [stand_in.file, stand_in.capture]
    return [path for path in recorded if (root / path).resolve() not in resolved]


def unheld_requests(stand_in: StandInRecord, root: Path) -> list[str]:
    if stand_in.capture is not None:
        # The capture's route keys are the words the stand-in branches on, not its file's text.
        return []
    text = (root / stand_in.file).read_text()
    return [output.request for output in stand_in.outputs if output.request not in text]


def unserved_captures(stand_in: StandInRecord, stand_in_dockerfile: Path, root: Path) -> list[str]:
    """A capture is served only by the generic stand-in, whose Dockerfile is
    `stand_in_dockerfile`."""
    if (
        stand_in.capture is None
        or (root / stand_in.file).resolve() == stand_in_dockerfile.resolve()
    ):
        return []
    return [stand_in.file]
