"""The defaults of a capture: probed on each scheme by `evals.capture_stand_in`, or kept.

`--keep-default SCHEME`, for a host that answers nothing on one scheme, sends no probe on that
scheme and carries its default over verbatim from the file at `--out`, which must exist and load
as a capture, so the tool still writes the whole file.
"""

import json
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import httpx
from pydantic import ValidationError

from evals.cve.public_stand_ins import StandInCapture

SCHEMES = ("http", "https")
FORM_SUFFIX = "%3Cx%3E%22%27"


@dataclass(frozen=True)
class CaptureRequest:
    method: str
    url: httpx.URL
    body: str | None = None
    form_field: str | None = None


def default_requests(
    host: str, probed_request_target: str, schemes: Sequence[str] = SCHEMES
) -> list[CaptureRequest]:
    request_targets = (probed_request_target, probed_request_target + FORM_SUFFIX)
    return [
        CaptureRequest("GET", httpx.URL(f"{scheme}://{host}{request_target}"))
        for request_target in request_targets
        for scheme in schemes
    ]


def probed_schemes(kept_scheme: str | None) -> list[str]:
    return [scheme for scheme in SCHEMES if scheme != kept_scheme]


def kept_defaults(out: Path, kept_scheme: str | None) -> list[dict[str, Any]]:
    if kept_scheme is None:
        return []
    try:
        text = out.read_text()
    except OSError as error:
        raise SystemExit(
            f"--keep-default {kept_scheme}: {out} cannot be read ({error}),"
            " and the kept default is carried over from it"
        ) from error
    try:
        StandInCapture.model_validate_json(text)
    except ValidationError as error:
        raise SystemExit(
            f"--keep-default {kept_scheme}: {out} does not load as a stand-in capture: {error}"
        ) from error
    return [each for each in json.loads(text)["defaults"] if each["scheme"] == kept_scheme]


def with_kept_defaults(record: dict[str, Any], kept: list[dict[str, Any]]) -> dict[str, Any]:
    defaults = sorted([*record["defaults"], *kept], key=lambda each: SCHEMES.index(each["scheme"]))
    return {**record, "defaults": defaults}
