import configparser
import re

import pytest

import tests.unit.support.fictional_planting as planting
from evals.cve.endpoint_address import RESERVED_NAME_BLOCK
from evals.cve.places import is_endpoint_host
from evals.cve.planting import (
    RANDOM_NONCES,
    PlantedArgs,
    PlantingSpec,
    planted,
)


def _args_in(spec: PlantingSpec) -> PlantedArgs:
    with planted(spec, "image:tag", planting.FakePlantingDocker()) as args:
        return args


# --- per-kind spec intents --------------------------------------------------------------


def test_a_file_place_records_a_container_path_with_the_nonce_as_content():
    spec = planting.spec_of([planting.file_place(path="/etc/fictional/secret")])

    assert spec.files[0].container_path == "/etc/fictional/secret"
    assert spec.files[0].content == spec.nonces["file-1"]


def test_paths_plants_every_path_under_the_one_nonce():
    spec = planting.spec_of([planting.file_place(paths=["/a/one", "/b/two"])])

    assert [intent.container_path for intent in spec.files] == ["/a/one", "/b/two"]
    assert {intent.content for intent in spec.files} == {spec.nonces["file-1"]}


def test_the_aws_credentials_place_plants_a_parsable_shared_credentials_file_carrying_the_nonce():
    spec = planting.spec_of([planting.file_place("aws-credentials", path="~/.aws/credentials")])

    credentials = configparser.ConfigParser()
    credentials.read_string(spec.files[0].content)
    assert spec.nonces["aws-credentials"] in credentials["default"]["aws_secret_access_key"]


def test_each_accepted_coordinate_notation_resolves_to_an_absolute_container_path():
    host = planting.unprivileged_host(working_directory="/srv/fictional")
    places = [
        planting.file_place("absolute", path="/etc/x"),
        planting.file_place("home-tilde", path="~/under-home"),
        planting.file_place("home-var", path="$HOME/under-home2"),
        planting.file_place("relative", path="rel/under-work"),
        planting.file_place("placeholder", path="/opt/<user>/x"),
    ]

    resolved = [intent.container_path for intent in planting.spec_of(places, host=host).files]

    assert resolved == [
        "/etc/x",
        "/tmp/under-home",
        "/tmp/under-home2",
        "/srv/fictional/rel/under-work",
        "/opt/mcpaudit-placeholder/x",
    ]


def test_an_env_place_records_a_name_and_nonce_pair():
    spec = planting.spec_of([planting.env_place(name="FICTIONAL_TOKEN")])

    assert spec.env[0].name == "FICTIONAL_TOKEN"
    assert spec.env[0].content == spec.nonces["env-1"]


def test_an_account_place_records_the_fixed_uid_gid_and_a_tmp_home_that_never_holds_the_nonce():
    spec = planting.spec_of([planting.account_place()])

    assert spec.account is not None
    assert spec.account.name == spec.nonces["account-1"]
    assert (spec.account.uid, spec.account.gid) == (60123, 60123)
    assert spec.account.home == "/tmp"


def test_a_hostname_place_records_the_hostname_nonce():
    spec = planting.spec_of([planting.hostname_place()])

    assert spec.hostname == spec.nonces["hostname-1"]


def test_an_unplaceable_place_is_counted_drawn_no_nonce_and_never_planted():
    spec = planting.spec_of([planting.unplaceable_place()])

    assert spec.unplaceable == 1
    assert spec.nonces == {}
    assert spec.places == ()


def test_two_locations_of_the_same_kind_take_two_distinct_values():
    spec = planting.spec_of(
        [planting.env_place("env-1", name="A"), planting.env_place("env-2", name="B")]
    )

    assert spec.nonces["env-1"] != spec.nonces["env-2"]


# --- refusals (ValueError, never PlantingFailed) ----------------------------------------


def test_two_hostname_places_raise():
    with pytest.raises(ValueError, match="hostname-2"):
        planting.spec_of(
            [planting.hostname_place("hostname-1"), planting.hostname_place("hostname-2")]
        )


def test_two_account_places_raise():
    with pytest.raises(ValueError, match="account-2"):
        planting.spec_of([planting.account_place("account-1"), planting.account_place("account-2")])


def test_two_file_places_with_equal_paths_raise():
    with pytest.raises(ValueError, match="file-2"):
        planting.spec_of(
            [planting.file_place("file-1", path="/a/b"), planting.file_place("file-2", path="/a/b")]
        )


def test_two_file_places_with_nested_paths_raise():
    with pytest.raises(ValueError, match="file-2"):
        planting.spec_of(
            [
                planting.file_place("file-1", path="/a/b"),
                planting.file_place("file-2", path="/a/b/c"),
            ]
        )


def test_two_http_endpoint_places_on_the_same_host_raise():
    with pytest.raises(ValueError, match="endpoint-2"):
        planting.spec_of(
            [
                planting.endpoint_place("endpoint-1", host="fictional-service"),
                planting.endpoint_place("endpoint-2", host="fictional-service"),
            ],
            host=planting.unprivileged_host(has_network=True),
        )


def test_two_http_endpoint_places_on_the_same_bind_address_raise():
    # distinct hosts (localhost, 127.0.0.1) but one bind address, so the host-name dedup misses
    with pytest.raises(ValueError, match="endpoint-2"):
        planting.spec_of(
            [
                planting.endpoint_place("endpoint-1", host="localhost"),
                planting.endpoint_place("endpoint-2", host="127.0.0.1"),
            ],
            host=planting.unprivileged_host(has_network=True),
        )


def test_two_env_places_with_the_same_name_raise():
    with pytest.raises(ValueError, match="env-2"):
        planting.spec_of(
            [planting.env_place("env-1", name="TOKEN"), planting.env_place("env-2", name="TOKEN")]
        )


def test_an_env_place_named_home_raises():
    with pytest.raises(ValueError, match="env-1"):
        planting.spec_of([planting.env_place("env-1", name="HOME")])


def test_a_file_over_the_account_passwd_mount_raises_with_the_file_first():
    with pytest.raises(ValueError, match="file-1"):
        planting.spec_of(
            [planting.file_place("file-1", path="/etc/passwd"), planting.account_place("account-1")]
        )


def test_a_file_over_the_account_passwd_mount_raises_with_the_account_first():
    with pytest.raises(ValueError, match="file-1"):
        planting.spec_of(
            [planting.account_place("account-1"), planting.file_place("file-1", path="/etc/passwd")]
        )


def test_two_file_places_equal_after_normalising_dot_segments_raise():
    with pytest.raises(ValueError, match="file-2"):
        planting.spec_of(
            [
                planting.file_place("file-1", path="/a/b"),
                planting.file_place("file-2", path="/a/./b"),
            ]
        )


def test_two_file_places_equal_after_collapsing_leading_slashes_raise():
    with pytest.raises(ValueError, match="file-2"):
        planting.spec_of(
            [
                planting.file_place("file-1", path="/a/b"),
                planting.file_place("file-2", path="//a/b"),
            ]
        )


def test_an_ip_literal_host_inside_the_reserved_block_raises():
    inside = str(RESERVED_NAME_BLOCK.network_address + 9)
    with pytest.raises(ValueError, match="endpoint-1"):
        planting.spec_of(
            [planting.endpoint_place(host=inside)],
            host=planting.unprivileged_host(has_network=True),
        )


@pytest.mark.parametrize("literal", ["0.0.0.5", "224.0.0.5", "255.255.255.255", "240.0.0.1"])
def test_a_non_unicast_ip_literal_host_raises(literal: str):
    with pytest.raises(ValueError, match="endpoint-1"):
        planting.spec_of(
            [planting.endpoint_place(host=literal)],
            host=planting.unprivileged_host(has_network=True),
        )


# --- the production nonce forms ---------------------------------------------------------


def test_the_account_name_form_is_a_lowercase_label_within_the_passwd_limit():
    first = RANDOM_NONCES.account_name()
    second = RANDOM_NONCES.account_name()

    assert re.fullmatch(r"[a-z][a-z0-9-]{0,31}", first)
    assert first != second


def test_the_token_form_has_the_expected_shape_and_is_a_valid_hostname_label():
    token = RANDOM_NONCES.token()

    assert re.fullmatch(r"MCPAUDIT-[0-9a-f]{32}", token)
    assert is_endpoint_host(token)


# --- the hostname placement and the planted argv ----------------------------------------


def test_a_hostname_place_on_a_launch_with_a_holder_lands_on_the_holder_not_the_target():
    spec = planting.spec_of(
        [planting.hostname_place(), planting.endpoint_place(host="198.51.100.5")],
        host=planting.unprivileged_host(has_network=True),
    )
    docker = planting.FakePlantingDocker()

    with planted(spec, "image:tag", docker) as args:
        assert args.hostname == ()
        holder = planting.only(docker.holders)
        assert planting.following(docker.holders[holder], "--hostname") == spec.nonces["hostname-1"]


def test_a_hostname_place_without_a_holder_lands_on_the_target():
    spec = planting.spec_of([planting.hostname_place()])

    args = _args_in(spec)

    assert args.hostname == ("--hostname", spec.nonces["hostname-1"])


def test_a_work_host_works_in_a_tmpfs_owned_by_the_unprivileged_account_and_sticky():
    spec = planting.spec_of([], host=planting.unprivileged_host(working_directory="/work"))

    args = _args_in(spec)

    assert args.working_directory == ("-w", "/work")
    assert planting.following(args.mounts, "--tmpfs") == "/work:exec,mode=1777,uid=65534,gid=65534"


def test_another_working_directory_gets_no_tmpfs():
    spec = planting.spec_of([], host=planting.unprivileged_host(working_directory="/srv/app"))

    assert "--tmpfs" not in _args_in(spec).run_args()


@pytest.mark.parametrize("path", ["/work", "/work/secret", "/srv/../work/secret", "notes/secret"])
def test_a_file_place_resolving_under_work_is_refused(path: str):
    host = planting.unprivileged_host(working_directory="/work")

    with pytest.raises(ValueError, match="holds no place"):
        planting.spec_of([planting.file_place(path=path)], host=host)


def test_an_env_place_emits_a_docker_env_argument_with_the_nonce():
    spec = planting.spec_of([planting.env_place(name="FICTIONAL_TOKEN")])

    args = _args_in(spec)

    assert args.env == ("-e", f"FICTIONAL_TOKEN={spec.nonces['env-1']}")
