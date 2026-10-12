import os
import re
import tempfile
from pathlib import Path

import pytest

import tests.unit.support.test_cve_planting_given as given
from evals.cve_places import Place, is_endpoint_host
from evals.cve_planting import (
    RANDOM_NONCES,
    DockerPlanting,
    NonceSource,
    PlantedArgs,
    PlantingFailed,
    PlantingHost,
    PlantingSpec,
    planted,
    planting_spec,
)
from evals.cve_planting_spec import RESERVED_NAME_BLOCK, served_file


def _spec_of(
    places: list[Place], host: PlantingHost | None = None, nonces: NonceSource | None = None
) -> PlantingSpec:
    return planting_spec(places, host or given.unprivileged_host(), nonces or given.FakeNonces())


def _args_in(spec: PlantingSpec, docker: given.FakePlantingDocker | None = None) -> PlantedArgs:
    with planted(spec, "image:tag", docker or given.FakePlantingDocker()) as args:
        return args


# --- per-kind spec intents --------------------------------------------------------------


def test_a_file_place_records_a_container_path_with_the_nonce_as_content():
    spec = _spec_of([given.file_place(path="/etc/fictional/secret")])

    assert spec.files[0].container_path == "/etc/fictional/secret"
    assert spec.files[0].content == spec.nonces["file-1"]


def test_paths_plants_every_path_under_the_one_nonce():
    spec = _spec_of([given.file_place(paths=["/a/one", "/b/two"])])

    assert [intent.container_path for intent in spec.files] == ["/a/one", "/b/two"]
    assert {intent.content for intent in spec.files} == {spec.nonces["file-1"]}


def test_each_accepted_coordinate_notation_resolves_to_an_absolute_container_path():
    host = given.unprivileged_host(working_directory="/srv/fictional")
    places = [
        given.file_place("absolute", path="/etc/x"),
        given.file_place("home-tilde", path="~/under-home"),
        given.file_place("home-var", path="$HOME/under-home2"),
        given.file_place("relative", path="rel/under-work"),
        given.file_place("placeholder", path="/opt/<user>/x"),
    ]

    resolved = [intent.container_path for intent in _spec_of(places, host=host).files]

    assert resolved == [
        "/etc/x",
        "/tmp/under-home",
        "/tmp/under-home2",
        "/srv/fictional/rel/under-work",
        "/opt/mcpaudit-placeholder/x",
    ]
    assert all(path.startswith("/") for path in resolved)


def test_an_env_place_records_a_name_and_nonce_pair():
    spec = _spec_of([given.env_place(name="FICTIONAL_TOKEN")])

    assert spec.env[0].name == "FICTIONAL_TOKEN"
    assert spec.env[0].content == spec.nonces["env-1"]


def test_an_account_place_records_the_fixed_uid_gid_and_a_tmp_home_that_never_holds_the_nonce():
    spec = _spec_of([given.account_place()])

    assert spec.account is not None
    assert spec.account.name == spec.nonces["account-1"]
    assert (spec.account.uid, spec.account.gid) == (60123, 60123)
    assert spec.account.home == "/tmp"
    assert spec.account.name not in spec.account.home


def test_a_hostname_place_records_the_hostname_nonce():
    spec = _spec_of([given.hostname_place()])

    assert spec.hostname == spec.nonces["hostname-1"]


def test_an_unplaceable_place_is_counted_drawn_no_nonce_and_never_planted():
    spec = _spec_of([given.unplaceable_place()])

    assert spec.unplaceable == 1
    assert spec.nonces == {}
    assert spec.places == ()


def test_the_spec_holds_no_host_path_container_or_network_name_nor_argv():
    docker = given.FakePlantingDocker()
    spec = _spec_of([given.file_place(path="/etc/x"), given.env_place()])

    # Only container-side intents and the drawn nonces, nothing a host or Docker call makes.
    assert docker.host_files == {} and docker.networks == set()
    assert spec.files[0].container_path == "/etc/x"
    assert set(spec.nonces) == {"file-1", "env-1"}


def test_two_locations_of_the_same_kind_take_two_distinct_values():
    spec = _spec_of([given.env_place("env-1", name="A"), given.env_place("env-2", name="B")])

    assert spec.nonces["env-1"] != spec.nonces["env-2"]


# --- refusals (ValueError, never PlantingFailed) ----------------------------------------


def test_an_account_place_on_a_host_user_launch_raises():
    with pytest.raises(ValueError, match="account-1"):
        planting_spec([given.account_place()], given.host_user_host(), given.FakeNonces())


def test_two_hostname_places_raise():
    with pytest.raises(ValueError, match="hostname-2"):
        _spec_of([given.hostname_place("hostname-1"), given.hostname_place("hostname-2")])


def test_two_account_places_raise():
    with pytest.raises(ValueError, match="account-2"):
        _spec_of([given.account_place("account-1"), given.account_place("account-2")])


def test_two_file_places_with_equal_paths_raise():
    with pytest.raises(ValueError, match="file-2"):
        _spec_of([given.file_place("file-1", path="/a/b"), given.file_place("file-2", path="/a/b")])


def test_two_file_places_with_nested_paths_raise():
    with pytest.raises(ValueError, match="file-2"):
        _spec_of(
            [given.file_place("file-1", path="/a/b"), given.file_place("file-2", path="/a/b/c")]
        )


def test_two_http_endpoint_places_on_the_same_host_raise():
    with pytest.raises(ValueError, match="endpoint-2"):
        _spec_of(
            [
                given.endpoint_place("endpoint-1", host="fictional-service"),
                given.endpoint_place("endpoint-2", host="fictional-service"),
            ],
            host=given.unprivileged_host(has_network=True),
        )


def test_two_http_endpoint_places_on_the_same_bind_address_raise():
    # distinct hosts (localhost, 127.0.0.1) but one bind address, so the host-name dedup misses
    with pytest.raises(ValueError, match="endpoint-2"):
        _spec_of(
            [
                given.endpoint_place("endpoint-1", host="localhost"),
                given.endpoint_place("endpoint-2", host="127.0.0.1"),
            ],
            host=given.unprivileged_host(has_network=True),
        )


def test_two_env_places_with_the_same_name_raise():
    with pytest.raises(ValueError, match="env-2"):
        _spec_of([given.env_place("env-1", name="TOKEN"), given.env_place("env-2", name="TOKEN")])


def test_an_env_place_named_home_raises():
    with pytest.raises(ValueError, match="env-1"):
        _spec_of([given.env_place("env-1", name="HOME")])


def test_a_file_over_the_account_passwd_mount_raises_with_the_file_first():
    with pytest.raises(ValueError, match="file-1"):
        _spec_of([given.file_place("file-1", path="/etc/passwd"), given.account_place("account-1")])


def test_a_file_over_the_account_passwd_mount_raises_with_the_account_first():
    with pytest.raises(ValueError, match="file-1"):
        _spec_of([given.account_place("account-1"), given.file_place("file-1", path="/etc/passwd")])


def test_two_file_places_equal_after_normalising_dot_segments_raise():
    with pytest.raises(ValueError, match="file-2"):
        _spec_of(
            [given.file_place("file-1", path="/a/b"), given.file_place("file-2", path="/a/./b")]
        )


def test_two_file_places_equal_after_collapsing_leading_slashes_raise():
    with pytest.raises(ValueError, match="file-2"):
        _spec_of(
            [given.file_place("file-1", path="/a/b"), given.file_place("file-2", path="//a/b")]
        )


def test_a_sentinel_that_does_not_serve_raises_and_leaves_nothing_alive():
    spec = _spec_of([given.endpoint_place(host="198.51.100.5")], host=given.unprivileged_host())
    docker = given.FakePlantingDocker(dead_sentinels=frozenset({"198.51.100.5"}))

    with (
        pytest.raises(PlantingFailed, match=re.escape("198.51.100.5")),
        planted(spec, "image:tag", docker),
    ):
        pass

    assert docker.networks == set()
    assert docker.holders == {}
    assert docker.sentinels == {}


def test_an_ip_literal_host_inside_the_reserved_block_raises():
    inside = str(RESERVED_NAME_BLOCK.network_address + 9)
    with pytest.raises(ValueError, match="endpoint-1"):
        _spec_of(
            [given.endpoint_place(host=inside)], host=given.unprivileged_host(has_network=True)
        )


@pytest.mark.parametrize("literal", ["0.0.0.5", "224.0.0.5", "255.255.255.255", "240.0.0.1"])
def test_a_non_unicast_ip_literal_host_raises(literal: str):
    with pytest.raises(ValueError, match="endpoint-1"):
        _spec_of(
            [given.endpoint_place(host=literal)], host=given.unprivileged_host(has_network=True)
        )


# --- the production nonce forms ---------------------------------------------------------


def test_the_account_name_form_is_a_lowercase_label_within_the_passwd_limit():
    first = RANDOM_NONCES.account_name()
    second = RANDOM_NONCES.account_name()

    assert re.fullmatch(r"[a-z][a-z0-9-]{0,31}", first)
    assert len(first) <= 32
    assert first != second


def test_the_token_form_has_the_expected_shape_and_is_a_valid_hostname_label():
    token = RANDOM_NONCES.token()

    assert re.fullmatch(r"MCPAUDIT-[0-9a-f]{32}", token)
    assert is_endpoint_host(token)


# --- endpoints: alias on the bridge, holder, address setups -----------------------------


def test_a_name_host_on_a_launch_with_a_network_is_an_alias_on_the_bridge_with_no_holder():
    spec = _spec_of(
        [given.endpoint_place(host="fictional-service", path="/p")],
        host=given.unprivileged_host(has_network=True),
    )
    docker = given.FakePlantingDocker()

    with planted(spec, "image:tag", docker) as args:
        assert spec.needs_holder is False
        assert docker.holders == {}
        network = next(iter(docker.networks))
        sentinel = docker.sentinels[_only(docker.sentinels)]
        assert _following(sentinel, "--network") == network
        assert _following(sentinel, "--network-alias") == "fictional-service"
        assert args.network == ("--network", network)


def test_an_ip_literal_host_yields_a_holder_address_setup_sentinel_and_target_network_args():
    spec = _spec_of(
        [given.endpoint_place(host="198.51.100.5", path="/p")],
        host=given.unprivileged_host(has_network=True),
    )
    docker = given.FakePlantingDocker()

    with planted(spec, "image:tag", docker) as args:
        network = next(iter(docker.networks))
        holder = _only(docker.holders)
        assert _following(docker.holders[holder], "--network") == network
        setup = _only_list(docker.address_setups)
        assert "NET_ADMIN" in setup and "--cap-drop" in setup
        assert "198.51.100.5/32" in setup
        sentinel = _only(docker.sentinels)
        assert _following(docker.sentinels[sentinel], "--network") == f"container:{holder}"
        assert "NET_BIND_SERVICE" in docker.sentinels[sentinel]
        assert "BIND_ADDR=198.51.100.5" in docker.sentinels[sentinel]
        assert args.network == ("--network", f"container:{holder}")


def test_an_ip_literal_host_without_network_holds_on_network_none():
    spec = _spec_of([given.endpoint_place(host="198.51.100.5")], host=given.unprivileged_host())
    docker = given.FakePlantingDocker()

    with planted(spec, "image:tag", docker) as args:
        assert docker.networks == set()
        holder = _only(docker.holders)
        assert _following(docker.holders[holder], "--network") == "none"
        assert args.network == ("--network", f"container:{holder}")


def test_two_ip_literal_hosts_share_one_holder():
    spec = _spec_of(
        [
            given.endpoint_place("endpoint-1", host="198.51.100.5"),
            given.endpoint_place("endpoint-2", host="203.0.113.7"),
        ],
        host=given.unprivileged_host(has_network=True),
    )
    docker = given.FakePlantingDocker()

    with planted(spec, "image:tag", docker):
        assert len(docker.holders) == 1
        assert len(docker.sentinels) == 2
        assert len(docker.address_setups) == 2


def test_a_loopback_literal_and_localhost_yield_a_holder_and_no_address_setup():
    spec = _spec_of(
        [
            given.endpoint_place("endpoint-1", host="127.0.0.5"),
            given.endpoint_place("endpoint-2", host="localhost"),
        ],
        host=given.unprivileged_host(has_network=True),
    )
    docker = given.FakePlantingDocker()

    with planted(spec, "image:tag", docker):
        assert len(docker.holders) == 1
        assert docker.address_setups == []
        bound = {_following(args, "-e", prefix="BIND_ADDR=") for args in docker.sentinels.values()}
        assert bound == {"BIND_ADDR=127.0.0.5", "BIND_ADDR=127.0.0.1"}


def test_a_name_host_without_network_adds_a_reserved_address_and_binds_the_sentinel_to_it():
    reserved = str(RESERVED_NAME_BLOCK.network_address + 1)
    spec = _spec_of(
        [given.endpoint_place(host="internal.fictional")], host=given.unprivileged_host()
    )

    assert spec.host_entries == (("internal.fictional", reserved),)
    assert spec.address_setups == (reserved,)
    docker = given.FakePlantingDocker()
    with planted(spec, "image:tag", docker):
        holder = _only(docker.holders)
        assert "--add-host" in docker.holders[holder]
        assert _following(docker.holders[holder], "--add-host") == f"internal.fictional:{reserved}"
        sentinel = _only(docker.sentinels)
        assert f"BIND_ADDR={reserved}" in docker.sentinels[sentinel]


def test_a_sentinel_is_told_the_file_httpd_serves_the_path_from():
    spec = _spec_of([given.endpoint_place(host="198.51.100.5", path="/fictional/dir/")])
    docker = given.FakePlantingDocker()

    with planted(spec, "image:tag", docker):
        sentinel = docker.sentinels[_only(docker.sentinels)]
        assert f"SERVE_FILE={served_file('/fictional/dir/')}" in sentinel
        assert not any(arg.startswith("SERVE_PATH=") for arg in sentinel)


def test_two_holder_bound_name_hosts_differing_only_in_case_raise_and_leave_nothing_alive():
    # Built directly, past the loader's lower-casing: the second name resolves to the first
    # sentinel, so a probe by name reads it as not serving.
    spec = _spec_of(
        [
            given.endpoint_place("endpoint-1", host="meta.fict"),
            given.endpoint_place("endpoint-2", host="META.fict"),
        ],
        host=given.unprivileged_host(),
    )
    docker = given.FakePlantingDocker()

    with pytest.raises(PlantingFailed), planted(spec, "image:tag", docker):
        pass

    assert docker.networks == set()
    assert docker.holders == {}
    assert docker.sentinels == {}


def test_an_upper_case_localhost_without_network_raises():
    spec = _spec_of([given.endpoint_place(host="LOCALHOST")], host=given.unprivileged_host())
    docker = given.FakePlantingDocker()

    with pytest.raises(PlantingFailed), planted(spec, "image:tag", docker):
        pass

    assert docker.networks == set()
    assert docker.holders == {}
    assert docker.sentinels == {}


def test_one_network_without_a_fixed_subnet_is_created_per_launch_with_a_network():
    with_network = _spec_of([given.file_place()], host=given.unprivileged_host(has_network=True))
    without = _spec_of([given.file_place()], host=given.unprivileged_host())

    docker_a = given.FakePlantingDocker()
    with planted(with_network, "image:tag", docker_a):
        assert len(docker_a.networks) == 1  # create_network takes no subnet, so none is fixed
    docker_b = given.FakePlantingDocker()
    with planted(without, "image:tag", docker_b):
        assert docker_b.networks == set()


# --- the hostname placement and the planted argv ----------------------------------------


def test_a_hostname_place_on_a_launch_with_a_holder_lands_on_the_holder_not_the_target():
    spec = _spec_of(
        [given.hostname_place(), given.endpoint_place(host="198.51.100.5")],
        host=given.unprivileged_host(has_network=True),
    )
    docker = given.FakePlantingDocker()

    with planted(spec, "image:tag", docker) as args:
        assert args.hostname == ()
        holder = _only(docker.holders)
        assert _following(docker.holders[holder], "--hostname") == spec.nonces["hostname-1"]


def test_a_hostname_place_without_a_holder_lands_on_the_target():
    spec = _spec_of([given.hostname_place()])

    args = _args_in(spec)

    assert args.hostname == ("--hostname", spec.nonces["hostname-1"])


def test_the_user_working_directory_and_network_args_follow_an_unprivileged_host():
    spec = _spec_of([], host=given.unprivileged_host(working_directory="/srv/fictional"))

    args = _args_in(spec)

    assert args.user == ("--user", "65534:65534", "-e", "HOME=/tmp")
    assert args.working_directory == ("-w", "/srv/fictional")
    assert args.network == ("--network", "none")


def test_a_host_user_launch_resolves_the_uid_only_at_planted():
    host = given.host_user_host(working_directory="/work")
    spec = _spec_of([], host=host)

    assert host.user.value == "host"  # the spec names the symbolic user, never a uid
    args = _args_in(spec)
    assert args.user == ("--user", f"{os.getuid()}:{os.getgid()}", "-e", "HOME=/tmp")


def test_an_env_place_emits_a_docker_env_argument_with_the_nonce():
    spec = _spec_of([given.env_place(name="FICTIONAL_TOKEN")])

    args = _args_in(spec)

    assert "-e" in args.env
    assert f"FICTIONAL_TOKEN={spec.nonces['env-1']}" in args.env


# --- account materialisation and file mode ----------------------------------------------


def test_a_planted_file_is_written_mode_0644_with_the_nonce():
    spec = _spec_of([given.file_place(path="/etc/x")])
    docker = given.FakePlantingDocker()

    with planted(spec, "image:tag", docker):
        host_file = _only_value(docker.host_files)
        assert host_file.mode == 0o644
        assert host_file.content == spec.nonces["file-1"]


def test_an_account_emits_a_passwd_entry_under_the_fixed_uid_and_replaces_the_user_args():
    spec = _spec_of([given.account_place()])
    docker = given.FakePlantingDocker()

    with planted(spec, "image:tag", docker) as args:
        name = spec.nonces["account-1"]
        assert args.user == ("--user", "60123:60123", "-e", "HOME=/tmp")
        assert "-v" in args.mounts
        passwd = _passwd_content(docker)
        assert "root:x:0:0" in passwd  # the image's own entries are kept
        assert f"{name}:x:60123:60123::/tmp:" in passwd
        assert name not in "/tmp"
        group = next(
            f.content for f in docker.host_files.values() if f"{name}:x:60123:\n" in f.content
        )
        assert "root:x:0:\n" in group  # the image's own group entries are kept


# --- failures and teardown --------------------------------------------------------------


def test_a_setup_failure_after_the_holder_undoes_everything_and_raises_planting_failed():
    spec = _spec_of(
        [
            given.endpoint_place("endpoint-1", host="198.51.100.5"),
            given.endpoint_place("endpoint-2", host="203.0.113.7"),
        ],
        host=given.unprivileged_host(has_network=True),
    )
    docker = given.FakePlantingDocker(fail={"start_sentinel": 1})  # the second sentinel fails

    with pytest.raises(PlantingFailed), planted(spec, "image:tag", docker):
        pass

    assert docker.networks == set()
    assert docker.holders == {}
    assert docker.sentinels == {}


def test_a_host_file_that_cannot_be_written_raises_planting_failed():
    spec = _spec_of([given.file_place(path="/etc/x")])
    docker = given.FakePlantingDocker(fail={"write_host_file": 0})

    with pytest.raises(PlantingFailed), planted(spec, "image:tag", docker):
        pass

    assert docker.host_files == {}


def test_teardown_leaves_nothing_alive_under_the_network_removal_refusal():
    spec = _spec_of(
        [given.endpoint_place(host="198.51.100.5"), given.file_place(path="/etc/x")],
        host=given.unprivileged_host(has_network=True),
    )
    docker = given.FakePlantingDocker()

    with planted(spec, "image:tag", docker):
        assert docker.networks and docker.holders and docker.sentinels and docker.host_files

    assert docker.networks == set()
    assert docker.holders == {}
    assert docker.sentinels == {}
    assert docker.host_files == {}


def test_a_teardown_failure_is_logged_and_does_not_raise():
    spec = _spec_of([given.endpoint_place(host="198.51.100.5")], host=given.unprivileged_host())
    docker = given.FakePlantingDocker(fail_teardown=frozenset({"remove_sentinel"}))

    with planted(spec, "image:tag", docker):  # no exception escapes the block
        pass


def test_a_non_infra_setup_failure_undoes_everything_and_re_raises_as_itself():
    spec = _spec_of(
        [given.endpoint_place(host="198.51.100.5"), given.file_place(path="/etc/x")],
        host=given.unprivileged_host(has_network=True),
    )
    docker = given.FakePlantingDocker(
        fail={"start_sentinel": 0}, fail_errors={"start_sentinel": RuntimeError("sentinel boom")}
    )

    with pytest.raises(RuntimeError, match="sentinel boom"), planted(spec, "image:tag", docker):
        pass

    assert docker.networks == set()
    assert docker.holders == {}
    assert docker.sentinels == {}
    assert docker.host_files == {}


def test_a_non_utf8_passwd_read_undoes_and_raises_planting_failed():
    spec = _spec_of([given.account_place()])
    decode_error = UnicodeDecodeError("utf-8", b"\xff", 0, 1, "invalid start byte")
    docker = given.FakePlantingDocker(
        fail={"image_accounts": 0}, fail_errors={"image_accounts": decode_error}
    )

    with pytest.raises(PlantingFailed), planted(spec, "image:tag", docker):
        pass

    assert docker.host_files == {}


def test_write_host_file_removes_the_temp_file_when_the_content_cannot_be_encoded(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    monkeypatch.setattr(tempfile, "tempdir", str(tmp_path))

    with pytest.raises(UnicodeEncodeError):
        DockerPlanting().write_host_file("\ud800", 0o644)

    assert list(tmp_path.iterdir()) == []


def _only(registry: dict[str, list[str]]) -> str:
    assert len(registry) == 1
    return next(iter(registry))


def _only_list(items: list[list[str]]) -> list[str]:
    assert len(items) == 1
    return items[0]


def _only_value(mapping: dict[str, given.HostFile]) -> given.HostFile:
    assert len(mapping) == 1
    return next(iter(mapping.values()))


def _following(args: list[str] | tuple[str, ...], flag: str, *, prefix: str | None = None) -> str:
    args = list(args)
    if prefix is not None:
        return next(value for value in args if value.startswith(prefix))
    return args[args.index(flag) + 1]


def _passwd_content(docker: given.FakePlantingDocker) -> str:
    return next(f.content for f in docker.host_files.values() if "root:x:0:0" in f.content)
