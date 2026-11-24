"""The Docker integration tests skip when a prerequisite is missing, and fail instead under
`CVE_PLANTING_REQUIRED=1`, set by the CI integration job and the detection calibration check job:
a green step there must mean the Docker path ran."""

import os
import shutil
from collections.abc import Sequence
from typing import NoReturn

import pytest

from evals.cve.images import ComposeImageStore, ImageBuildFailed, ensure_images
from evals.cve.planting_base import SENTINEL_SERVICE, STAND_IN_SERVICE
from mcp_auditor.adapters.docker import DockerRuntime


def image_prerequisites(services: Sequence[str]) -> None:
    missing = missing_prerequisite()
    if missing is not None:
        skip_or_require(missing)
    _ensure_or_fail(services)


def stand_in_prerequisites() -> None:
    missing = missing_prerequisite() or _missing_openssl()
    if missing is not None:
        skip_or_require(missing)
    _ensure_or_fail([SENTINEL_SERVICE, STAND_IN_SERVICE])


def missing_prerequisite() -> str | None:
    if not DockerRuntime().available():
        return "this test needs Docker"
    return None


def skip_or_require(missing: str) -> NoReturn:
    if os.environ.get("CVE_PLANTING_REQUIRED") == "1":
        pytest.fail(missing)
    pytest.skip(missing)


def _ensure_or_fail(services: Sequence[str]) -> None:
    try:
        ensure_images(services, ComposeImageStore())
    except ImageBuildFailed as error:
        pytest.fail(str(error))


def _missing_openssl() -> str | None:
    return None if shutil.which("openssl") else "the planted stand-in needs openssl"
