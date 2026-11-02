"""The stand-in captures (`evals/stand_ins/<host>.json`) and their loader.

A capture records what a public service answered at one date, and the stand-in image replays
it under the service's real name inside a closed fixture network. A target names a stand-in by
its host only: nothing is read at import, the planting and the fixture fingerprint load the
capture at call time, and a test passes its own directory. The leaf, its key and the fixture
authority sit beside the captures under `tls/`, made by `tls/generate.sh`.
"""

from dataclasses import dataclass
from ipaddress import IPv4Address
from pathlib import Path
from typing import Annotated, Literal

from pydantic import AfterValidator, BaseModel, ConfigDict, Field

from evals.cve_planting_base import StandIn

STAND_INS_DIRECTORY = Path(__file__).parent / "stand_ins"


def _global_unicast(address: str) -> str:
    parsed = IPv4Address(address)
    if not parsed.is_global or parsed.is_multicast:
        raise ValueError("address is not a global unicast IPv4")
    return address


class StandInRoute(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    scheme: Literal["http", "https"]
    method: str
    target: str
    status: int
    headers: list[tuple[str, str]]
    body: str


class StandInCapture(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    host: str
    address: Annotated[str, AfterValidator(_global_unicast)]
    captured_at: str = Field(min_length=1)
    command: str = Field(min_length=1)
    request_headers: list[tuple[str, str]]
    routes: list[StandInRoute]


@dataclass(frozen=True)
class StandInFiles:
    capture: Path
    certificate: Path
    key: Path
    authority: Path


def stand_in(host: str, directory: Path = STAND_INS_DIRECTORY) -> StandIn:
    files = stand_in_files(host, directory)
    text = files.capture.read_text()
    capture = StandInCapture.model_validate_json(text)
    if capture.host != host:
        raise ValueError(f"{files.capture.name}: host is {capture.host}, not its file's {host}")
    return StandIn(
        host=host,
        address=capture.address,
        capture=text,
        certificate=files.certificate.read_text(),
        key=files.key.read_text(),
        authority=files.authority.read_text(),
    )


def stand_in_files(host: str, directory: Path = STAND_INS_DIRECTORY) -> StandInFiles:
    tls = directory / "tls"
    return StandInFiles(
        capture=directory / f"{host}.json",
        certificate=tls / f"{host}.pem",
        key=tls / f"{host}-key.pem",
        authority=tls / "fixture-authority.pem",
    )
