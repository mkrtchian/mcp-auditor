"""The stand-in captures (`evals/stand_ins/<host>.json`) and their loader.

A capture records what a public service answered at one date, and the stand-in image serves
it under the service's real name inside a closed fixture network. A target names a stand-in by
its host only: nothing is read at import, the planting and the fixture fingerprint load the
capture at call time, and a test passes its own directory. A capture also records, on each
scheme, the default answer (`stand_in_defaults.py`): what the host answered for a generated path
it does not have, which the stand-in serves for any request its routes lack. Every answer
carries its captured headers, the connection and framing ones apart, with a `Content-Length` of
the stand-in's own, every route but a captured `HEAD` framed by the body it serves.

A `POST` route written by hand may carry the action it answers, which the stand-in reads from the
request. For an AWS service it is the full `X-Amz-Target` value for the JSON protocol (for example
`secretsmanager.GetSecretValue`), the bare `Action` field of a form body for the query protocol (for
example `DescribeDBInstances`). For a GraphQL API it is the operation name the `query` of a JSON
body declares (for example `IssueList` for `api.github.com`). A request whose action no route names
gets the action-less route of its request target, else the default, as the real service answers an
action it does not know with an error. The capture command records no action: those routes are
written by hand from the services' published examples, since a real capture would need signed or
authenticated requests.

A route with an action may also be keyed on the value of one identifier at a fixed position of the
request: a field of a form body (`form`), a top-level member of a JSON body whatever its media type
(`json_member`), or a member of the `variables` object of a GraphQL request (`graphql_variable`).
The keyed route answers the request whose value at that position equals its own, string or integer,
compared exactly and with its type. Its action's error route, the route of the same request target
and action with no identifier, answers every other value and a request with none, so a keyed action
always has one. The keyed routes of one action read one identifier, one location and one name.

A `POST` route may instead carry a form field: a request whose
`application/x-www-form-urlencoded` body carries that field gets the route, else the
field-less route of its request target, else the default. The route is chosen on a fixed word at a
fixed position of the request, the field's name.

A file is either a capture (`source` `capture`, dated by `captured_at`) or written by hand
from the software's documentation or published examples (`source` `software_sources`, no
`captured_at`, `command` naming the documentation it follows). A written file's `address` is a
fixed global address of the fixture, not a resolution of the host.

The leaf, its key and the fixture authority sit beside the captures under `tls/`, made by
`tls/generate.sh`.
"""

from collections import defaultdict
from dataclasses import dataclass
from ipaddress import IPv4Address
from pathlib import Path
from typing import Annotated, Literal, Self

from pydantic import (
    AfterValidator,
    BaseModel,
    ConfigDict,
    Field,
    StrictInt,
    StrictStr,
    model_validator,
)

from evals.cve.planting_base import StandIn
from evals.cve.stand_in_defaults import StandInDefault

type _ActionKey = tuple[str, str, str, str | None]

STAND_INS_DIRECTORY = Path(__file__).parents[1] / "stand_ins"


def _global_unicast(address: str) -> str:
    parsed = IPv4Address(address)
    if not parsed.is_global or parsed.is_multicast:
        raise ValueError("address is not a global unicast IPv4")
    return address


class RouteIdentifier(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    location: Literal["form", "json_member", "graphql_variable"]
    name: str = Field(min_length=1)
    value: StrictStr | StrictInt

    @model_validator(mode="after")
    def _a_form_carries_text(self) -> Self:
        if self.location == "form" and not isinstance(self.value, str):
            raise ValueError("a form identifier's value is a string, since a form carries text")
        return self


class StandInRoute(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    scheme: Literal["http", "https"]
    method: str
    request_target: str
    status: int
    headers: list[tuple[str, str]]
    body: str
    action: str | None = None
    form_field: str | None = None
    identifier: RouteIdentifier | None = None

    @model_validator(mode="after")
    def _an_action_or_a_form_field_keys_a_post_only(self) -> Self:
        if self.action is not None and self.method != "POST":
            raise ValueError("only a POST route carries an action")
        if self.form_field is not None and self.method != "POST":
            raise ValueError("only a POST route carries a form field")
        if self.action is not None and self.form_field is not None:
            raise ValueError(
                "a route is keyed on an action or a form field, never both,"
                " since the stand-in looks them up one after the other"
            )
        return self

    @model_validator(mode="after")
    def _an_identifier_keys_an_action(self) -> Self:
        if self.identifier is not None and self.action is None:
            raise ValueError(
                "an identifier keys a route that carries an action,"
                " since the stand-in reads it only for a request naming one"
            )
        return self


class StandInCapture(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    host: str
    address: Annotated[str, AfterValidator(_global_unicast)]
    source: Literal["capture", "software_sources"]
    captured_at: str | None = Field(default=None, min_length=1)
    command: str = Field(min_length=1)
    request_headers: list[tuple[str, str]]
    routes: list[StandInRoute]
    defaults: list[StandInDefault]

    @model_validator(mode="after")
    def _a_date_only_on_a_capture(self) -> Self:
        if (self.captured_at is not None) != (self.source == "capture"):
            raise ValueError(
                "captured_at dates a capture, so a capture carries it"
                " and a file written from the software's sources does not"
            )
        return self

    @model_validator(mode="after")
    def _one_default_per_scheme(self) -> Self:
        if sorted(default.scheme for default in self.defaults) != ["http", "https"]:
            raise ValueError(
                "the stand-in serves both schemes,"
                " so a capture records the answer to an unknown path on each"
            )
        return self

    @model_validator(mode="after")
    def _one_route_per_key(self) -> Self:
        keys = [
            (
                each.scheme,
                each.method,
                each.request_target,
                each.action,
                each.form_field,
                each.identifier,
            )
            for each in self.routes
        ]
        if len(set(keys)) != len(keys):
            raise ValueError(
                "two routes answer one"
                " (scheme, method, request_target, action, form_field, identifier),"
                " so the stand-in could serve only one of them"
            )
        return self

    @model_validator(mode="after")
    def _every_keyed_action_has_its_error_route(self) -> Self:
        unkeyed = {_action_key(each) for each in self.routes if each.identifier is None}
        keyed = {_action_key(each) for each in self.routes if each.identifier is not None}
        if not keyed <= unkeyed:
            raise ValueError(
                "a keyed action needs its error route, the route of its request target and action"
                " with no identifier, since the real service answers another value with an error"
            )
        return self

    @model_validator(mode="after")
    def _the_keyed_routes_of_one_action_read_one_identifier(self) -> Self:
        read: defaultdict[_ActionKey, set[tuple[str, str]]] = defaultdict(set)
        for each in self.routes:
            if each.identifier is not None:
                read[_action_key(each)].add((each.identifier.location, each.identifier.name))
        if any(len(identifiers) > 1 for identifiers in read.values()):
            raise ValueError(
                "the keyed routes of one action share one location and one name,"
                " so the stand-in reads one identifier per action"
            )
        return self


def _action_key(route: StandInRoute) -> _ActionKey:
    return (route.scheme, route.method, route.request_target, route.action)


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
