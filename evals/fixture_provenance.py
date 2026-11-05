"""Where a fixture's stand-in outputs come from, shared by the nuisance admission and the holdout
calibration card: what the stand-in replaces, why the real software cannot run under the
confinement, the repository file that implements it, and the source of each output it serves.
Beside it, the release of each real software a fixture runs.
"""

from datetime import date
from typing import Literal

from pydantic import BaseModel

# software_sources: the software's documentation, fixtures, tests and published API examples.
SourceKind = Literal["real_software", "capture", "software_sources", "server_tests", "invented"]


class IdentifierReplacement(BaseModel):
    original: str
    replacement: str


class StandInOutput(BaseModel):
    request: str  # the fixed words at fixed positions of the request it answers
    source: SourceKind
    citation: str
    form_source: str | None = None  # the source whose form an invented output follows
    replacements: list[IdentifierReplacement] = []


class StandInRecord(BaseModel):
    replaces: str  # the program, device, HTTP backend or public host
    reason: str  # why the real software cannot run under the confinement
    # The repository path of what implements it: a responder Dockerfile, a backend module, a
    # stub-writing run Dockerfile.
    file: str
    capture: str | None = None  # an evals/stand_ins/ capture that sources every route
    outputs: list[StandInOutput]


class SoftwareRelease(BaseModel):
    software: str  # as its documentation names it
    release: str
    day: date | None  # the day the release was the current stable one, None when the docs name it
    source: str  # the line of documentation or the release page that gives it


def software_release_problems(release: SoftwareRelease) -> list[str]:
    blank = [
        field
        for field, value in (
            ("software", release.software),
            ("release", release.release),
            ("source", release.source),
        )
        if not value.strip()
    ]
    return [f"software release of {release.software} records no {field}" for field in blank]


def stand_in_problems(stand_in: StandInRecord) -> list[str]:
    problems: list[str] = []
    if not stand_in.reason.strip():
        problems.append("records no reason the real software cannot run")
    if not stand_in.outputs and stand_in.capture is None:
        problems.append("records neither an output nor a capture")
    for output in stand_in.outputs:
        problems += _output_problems(output)
    return [f"stand-in for {stand_in.replaces}: {problem}" for problem in problems]


def _output_problems(output: StandInOutput) -> list[str]:
    invented = output.source == "invented"
    if invented and output.form_source is None:
        return [f"invented output for {output.request!r} names no form source"]
    if not invented and output.form_source is not None:
        return [f"{output.source} output for {output.request!r} names a form source"]
    if invented and output.replacements:
        return [f"invented output for {output.request!r} records identifier replacements"]
    return []
