# The proof that a server under the unprivileged account resolves the mounted layout by absolute
# path and from its parent, as a deployed server does, the temp root under it being 0700.
#
# Skipped without Docker, failed under `CVE_PLANTING_REQUIRED=1`, as `test_cve_planting.py`. A
# missing or foreign sentinel image is rebuilt through compose before the first case.
import os

import pytest

import tests.integration.support.test_cve_layout_mount_given as given
from evals.cve_images import ComposeImageStore, ImageBuildFailed, ensure_images
from evals.cve_layout import build_empty_layout
from evals.cve_planting_base import SENTINEL_SERVICE


@pytest.fixture(autouse=True, scope="module")
def _docker_prerequisites() -> None:
    missing = given.missing_prerequisite()
    if missing is not None:
        if os.environ.get("CVE_PLANTING_REQUIRED") == "1":
            pytest.fail(missing)
        pytest.skip(missing)
    try:
        ensure_images([SENTINEL_SERVICE], ComposeImageStore())
    except ImageBuildFailed as error:
        pytest.fail(str(error))


def test_an_unprivileged_server_resolves_the_layout_by_absolute_path_and_from_its_parent():
    commands = ["cat /srv/.env", "cat ../.env", "ls /srv/app.git", "cat /srv/app/.git/config"]

    results = given.an_unprivileged_server_reads(given.the_full_layout, commands)

    assert {command: result.exit_code for command, result in results.items()} == dict.fromkeys(
        commands, 0
    ), results


def test_an_unprivileged_server_resolves_the_empty_layout_by_absolute_path():
    commands = ["ls /srv/app.git", "ls /srv/app/.git"]

    results = given.an_unprivileged_server_reads(build_empty_layout, commands)

    assert {command: result.exit_code for command, result in results.items()} == dict.fromkeys(
        commands, 0
    ), results
