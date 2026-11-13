"""The default answer of a stand-in capture: what the host answered on one scheme for a generated
path it does not have, which the stand-in serves for any request its routes lack.

The stand-in quotes the request target wherever the host quoted the probed one, in `Location` as
sent and in an HTML or JSON body in the measured form (`path_form`), escaped as the body's media
type escapes it.
"""

import json
import re
from collections.abc import Sequence
from typing import Literal, Self

from pydantic import BaseModel, ConfigDict, Field, model_validator

QUOTING_MEDIA_TYPES = ("text/html", "application/json")
# markupsafe's table, the one CKAN's Jinja uses; `html.escape` writes `&quot;` and `&#x27;`.
_HTML_ESCAPES = (("&", "&amp;"), ("<", "&lt;"), (">", "&gt;"), ('"', "&#34;"), ("'", "&#39;"))


class StandInDefault(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    scheme: Literal["http", "https"]
    probed_request_target: str = Field(pattern=r"^/[0-9a-f]{16}$")
    status: int
    headers: list[tuple[str, str]]
    body: str
    path_form: Literal["decoded", "raw"] | None

    @model_validator(mode="after")
    def _quotes_its_request_target_only_where_the_stand_in_substitutes_it(self) -> Self:
        others = [value for name, value in self.headers if name.lower() != "location"]
        if any(self.probed_request_target in value for value in others):
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
        quoted = len(re.findall(rf"(?<!\\){re.escape(self.probed_request_target)}", text))
        return text.count(self.probed_request_target[1:]) == quoted

    @model_validator(mode="after")
    def _path_form_says_how_a_known_body_escaping_quotes_its_request_target(self) -> Self:
        quotes = self.probed_request_target in self.body
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
