from pathlib import Path

import pytest

import tests.unit.support.test_confinement_given as given
from mcp_auditor.domain.confinement import (
    DeclaredMount,
    MissingMountError,
    MountSpec,
    RefusedMountError,
    UnspellableMountError,
    is_declared_container,
    parse_mount_option,
    refused_roots,
)


def test_spellings_to_resolve_covers_paths_words_declared_and_refused():
    policy = given.a_policy("/data:rw")

    args = ["/abs", "./rel", "build", "--flag", "--root=./x", "-v"]

    spellings = policy.spellings_to_resolve(args)

    assert set(spellings) == {"/abs", "./rel", "build", "/data"} | {
        str(root) for root in refused_roots(given.HOME)
    }


def test_mounts_an_existing_absolute_argv_path_writable():
    plan = given.a_policy().plan(["server", "/data/repo"], {"/data/repo": Path("/data/repo")})

    assert plan.mounts == (MountSpec(host=Path("/data/repo"), writable=True),)
    assert plan.rewrites == {}


def test_rewrites_a_relative_argv_path_to_its_absolute_form():
    resolved = {"./data": Path("/home/alice/proj/data"), ".": Path("/home/alice/proj")}

    plan = given.a_policy().plan(["./data", "."], resolved)

    assert plan.mounts == (
        MountSpec(host=Path("/home/alice/proj/data"), writable=True),
        MountSpec(host=Path("/home/alice/proj"), writable=True),
    )
    assert plan.rewrites == {"./data": "/home/alice/proj/data", ".": "/home/alice/proj"}


def test_ignores_a_path_shaped_element_that_does_not_exist():
    plan = given.a_policy().plan(["/nowhere", "--root=./data"], {})

    assert plan.mounts == ()
    assert plan.rewrites == {}


def test_reports_an_existing_bare_word_without_mounting_it():
    plan = given.a_policy().plan(["build"], {"build": Path("/home/alice/proj/build")})

    assert plan.unmounted_existing == ("build",)
    assert plan.mounts == ()
    assert plan.rewrites == {}


def test_parse_mount_option_defaults_to_read_only():
    assert parse_mount_option("/data") == DeclaredMount(spelling="/data", writable=False)


def test_parse_mount_option_reads_the_trailing_mode():
    assert parse_mount_option("/data:rw") == DeclaredMount(spelling="/data", writable=True)
    assert parse_mount_option("/data:ro") == DeclaredMount(spelling="/data", writable=False)


def test_parse_mount_option_keeps_any_other_colon_in_the_path():
    assert parse_mount_option("/da:ta") == DeclaredMount(spelling="/da:ta", writable=False)


def test_mounts_a_declared_path_that_argv_never_names():
    plan = given.a_policy("/secrets").plan(["server"], {"/secrets": Path("/secrets")})

    assert plan.mounts == (MountSpec(host=Path("/secrets"), writable=False),)


def test_declared_mount_absent_from_the_host_is_refused():
    with pytest.raises(MissingMountError):
        given.a_policy("/nowhere:rw").plan([], {})


def test_refused_root_in_argv_is_refused():
    with pytest.raises(RefusedMountError):
        given.a_policy().plan(["/home"], {"/home": Path("/home")})


def test_refused_root_is_accepted_when_declared_and_also_in_argv():
    plan = given.a_policy("/home:rw").plan(["/home"], {"/home": Path("/home")})

    assert plan.mounts == (MountSpec(host=Path("/home"), writable=True),)


def test_path_under_a_refused_root_is_accepted():
    resolved = {"/home/alice/proj": Path("/home/alice/proj")}

    plan = given.a_policy().plan(["/home/alice/proj"], resolved)

    assert plan.mounts == (MountSpec(host=Path("/home/alice/proj"), writable=True),)


def test_refused_root_reached_through_a_symlink_is_refused():
    resolved = {"/home": Path("/var/home"), "/home/x/..": Path("/var/home")}

    with pytest.raises(RefusedMountError):
        given.a_policy().plan(["/home/x/.."], resolved)


def test_a_host_path_reached_twice_yields_one_mount_and_the_declared_flag_wins():
    resolved = {"/data": Path("/data"), "./data": Path("/data")}

    plan = given.a_policy("/data:ro").plan(["/data", "./data"], resolved)

    assert plan.mounts == (MountSpec(host=Path("/data"), writable=False),)


def test_a_path_holding_a_double_quote_cannot_be_mounted():
    spelling = '/srv/we"ird'

    with pytest.raises(UnspellableMountError):
        given.a_policy().plan([spelling], {spelling: Path(spelling)})


def test_a_path_holding_a_carriage_return_before_a_line_feed_cannot_be_mounted():
    spelling = "/srv/we\r\nird"

    with pytest.raises(UnspellableMountError):
        given.a_policy().plan([spelling], {spelling: Path(spelling)})


@pytest.mark.parametrize("spelling", ["/srv/weird ", "/srv/weird\t", "/srv/weird\n"])
def test_a_path_ending_in_whitespace_cannot_be_mounted(spelling: str):
    with pytest.raises(UnspellableMountError):
        given.a_policy().plan([spelling], {spelling: Path(spelling)})


@pytest.mark.parametrize("spelling", ["/srv/we\rird", "/srv/we ird", "/srv/we\tird", "/srv/we'ird"])
def test_a_path_docker_can_still_spell_is_mounted(spelling: str):
    plan = given.a_policy().plan([spelling], {spelling: Path(spelling)})

    assert plan.mounts == (MountSpec(host=Path(spelling), writable=True),)


def test_a_declared_mount_is_refused_on_the_same_characters():
    spelling = '/srv/we"ird'

    with pytest.raises(UnspellableMountError):
        given.a_policy(f"{spelling}:rw").plan([], {spelling: Path(spelling)})


def test_refused_roots_hold_the_home_itself_and_not_its_children():
    roots = refused_roots(Path("/home/alice"))

    assert Path("/home/alice") in roots
    assert Path("/home/alice/project") not in roots


def test_a_docker_run_command_is_a_declared_container():
    assert is_declared_container("docker", ("run", "img"))
    assert is_declared_container("docker", ["run", "img"])


def test_other_container_spellings_are_not_declared_containers():
    assert not is_declared_container("docker", ["container", "run"])
    assert not is_declared_container("podman", ["run"])
    assert not is_declared_container("docker", [])
