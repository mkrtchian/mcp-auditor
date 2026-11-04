"""The stand-in captures (`evals/stand_ins/<host>.json`) and their loader.

A capture records what a public service answered at one date, and the stand-in image replays
it under the service's real name inside a closed fixture network. A target names a stand-in by
its host only: nothing is read at import, the planting and the fixture fingerprint load the
capture at call time, and a test passes its own directory. A capture also records, on each
scheme, the default answer: what the host answered for a generated path it does not have, which
the stand-in replays for any request its routes lack. The stand-in quotes the request's target
wherever the host quoted the probed one, in `Location` as sent and in an HTML or JSON body in
the measured form (`path_form`), escaped as the body's media type escapes it. The leaf, its key
and the fixture authority sit beside the captures under `tls/`, made by `tls/generate.sh`.
"""

import json
import re
from collections.abc import Sequence
from dataclasses import dataclass
from ipaddress import IPv4Address
from pathlib import Path
from typing import Annotated, Literal, Self

from pydantic import AfterValidator, BaseModel, ConfigDict, Field, model_validator

from evals.cve_planting_base import StandIn

STAND_INS_DIRECTORY = Path(__file__).parent / "stand_ins"
QUOTING_MEDIA_TYPES = ("text/html", "application/json")
# markupsafe's table, the one CKAN's Jinja uses; `html.escape` writes `&quot;` and `&#x27;`.
_HTML_ESCAPES = (("&", "&amp;"), ("<", "&lt;"), (">", "&gt;"), ('"', "&#34;"), ("'", "&#39;"))


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


class StandInDefault(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    scheme: Literal["http", "https"]
    probed_target: str = Field(pattern=r"^/[0-9a-f]{16}$")
    status: int
    headers: list[tuple[str, str]]
    body: str
    path_form: Literal["decoded", "raw"] | None

    @model_validator(mode="after")
    def _quotes_its_target_only_where_the_stand_in_substitutes_it(self) -> Self:
        others = [value for name, value in self.headers if name.lower() != "location"]
        if any(self.probed_target in value for value in others):
            raise ValueError(
                "the default answer quotes the request in a header other than its Location,"
                " which the stand-in does not reproduce"
            )
        texts = (self.body, *(value for _, value in self.headers))
        if not all(self._in_path_position(text) for text in texts):
            raise ValueError(
                "the probed path appears outside path position,"
                " so a substitution would rewrite an unrelated value"
            )
        return self

    def _in_path_position(self, text: str) -> bool:
        # A backslash before the slash makes it half of an escape (JSON's `\/`), not the path's.
        quoted = len(re.findall(rf"(?<!\\){re.escape(self.probed_target)}", text))
        return text.count(self.probed_target[1:]) == quoted

    @model_validator(mode="after")
    def _path_form_says_how_a_known_body_escaping_quotes_its_target(self) -> Self:
        quotes = self.probed_target in self.body
        if quotes and media_type(self.headers) not in QUOTING_MEDIA_TYPES:
            raise ValueError(
                "the default answer quotes the request in a body that is neither HTML nor JSON,"
                " whose escaping the stand-in does not know"
            )
        if quotes != (self.path_form is not None):
            raise ValueError(
                "path_form must say how the body quotes the request, and only when it does"
            )
        return self


class StandInCapture(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    host: str
    address: Annotated[str, AfterValidator(_global_unicast)]
    captured_at: str = Field(min_length=1)
    command: str = Field(min_length=1)
    request_headers: list[tuple[str, str]]
    routes: list[StandInRoute]
    defaults: list[StandInDefault]

    @model_validator(mode="after")
    def _one_default_per_scheme(self) -> Self:
        if sorted(default.scheme for default in self.defaults) != ["http", "https"]:
            raise ValueError(
                "the stand-in serves both schemes,"
                " so a capture records the answer to an unknown path on each"
            )
        return self


def media_type(headers: Sequence[tuple[str, str]]) -> str | None:
    for name, value in headers:
        if name.lower() == "content-type":
            return value.split(";", 1)[0].strip().lower()
    return None


def body_quoting(value: str, media: str) -> str:
    if media == "text/html":
        for raw, escaped in _HTML_ESCAPES:
            value = value.replace(raw, escaped)
        return value
    if media == "application/json":
        return json.dumps(value)[1:-1]
    raise ValueError(f"a {media} body has no escaping the stand-in knows")


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
