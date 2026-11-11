# The proof that a server under the unprivileged account resolves the mounted layout by absolute
# path and from its parent, as a deployed server does, the temp root under it being 0700, that a
# server under the planted account, which owns none of the tree, resolves it too, that
# the real adapter hands every node over to that account, and that it removes whatever a
# read-write server left in the tree.
#
# Skipped without Docker, failed under `CVE_PLANTING_REQUIRED=1`, as `test_cve_planting.py`. A
# missing or foreign sentinel or git image is rebuilt through compose before the first case, and
# the first case pulls the pinned busybox the hand-over and the removal run.
import os

import pytest

import tests.integration.support.test_cve_layout_mount_given as given
from evals.cve.images import ComposeImageStore, ImageBuildFailed, ensure_images
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
        ensure_images([SENTINEL_SERVICE, given.GIT_SERVICE], ComposeImageStore())
    except ImageBuildFailed as error:
        pytest.fail(str(error))


def test_an_unprivileged_server_resolves_the_layout_by_absolute_path_and_from_its_parent():
    commands = ["cat /srv/.env", "cat ../.env", "ls /srv/app.git", "cat /srv/app/.git/config"]

    results = given.an_unprivileged_server_reads(given.the_full_layout, commands)

    assert {command: result.exit_code for command, result in results.items()} == dict.fromkeys(
        commands, 0
    ), results


def test_a_server_under_the_planted_account_resolves_the_layout_it_does_not_own():
    commands = ["cat /srv/.env", "ls /srv/app.git", "cat /srv/app/.git/config"]

    results = given.an_unprivileged_server_reads(
        given.the_full_layout, commands, user=given.the_planted_account()
    )

    assert {command: result.exit_code for command, result in results.items()} == dict.fromkeys(
        commands, 0
    ), results


def test_an_unprivileged_server_resolves_the_empty_layout_by_absolute_path():
    commands = ["ls /srv/app.git", "ls /srv/app/.git"]

    results = given.an_unprivileged_server_reads(build_empty_layout, commands)

    assert {command: result.exit_code for command, result in results.items()} == dict.fromkeys(
        commands, 0
    ), results


@pytest.mark.parametrize(
    "builder", [given.the_full_layout, build_empty_layout], ids=["full", "empty"]
)
def test_every_node_of_the_layout_belongs_to_the_unprivileged_account(
    builder: given.LayoutBuilder,
):
    command = "find /srv ! -user 65534 -o ! -group 65534"

    results = given.an_unprivileged_server_reads(builder, [command])

    assert results[command] == given.CommandResult(0, ""), results


def test_a_server_on_the_read_write_git_launch_writes_to_the_checkout_and_git_accepts_it():
    run = given.an_unprivileged_server_on_the_git_launch_runs(
        "touch /srv/app/written && git -C /srv/app status --short"
    )

    assert run.result.exit_code == 0, run.result.output
    assert "written" in run.result.output
    assert not run.root.parent.exists()


def test_nothing_a_read_write_server_leaves_in_a_sticky_directory_outlives_the_launch():
    run = given.an_unprivileged_server_on_the_git_launch_runs(
        "mkdir /srv/sticky && chmod 1777 /srv/sticky && touch /srv/sticky/owned"
    )

    assert run.result.exit_code == 0, run.result.output
    assert not run.root.parent.exists()
