import pytest

import tests.unit.support.test_doris_serialization_given as given
from evals import cve_environments
from evals.doris_backend import DORIS_SERVER_LAUNCH, doris_server_args, user_args


def _strip_pair(args: list[str], flag: str) -> list[str]:
    i = args.index(flag)
    return args[:i] + args[i + 2 :]


def _without(args: list[str], segment: list[str]) -> list[str]:
    for i in range(len(args) - len(segment) + 1):
        if args[i : i + len(segment)] == segment:
            return args[:i] + args[i + len(segment) :]
    raise AssertionError(f"{segment} not found in {args}")


def _follows(args: list[str], flag: str, value: str) -> bool:
    return args[args.index(flag) + 1] == value


def test_the_helper_and_the_holdout_env_agree_on_the_launch_tail(monkeypatch: pytest.MonkeyPatch):
    given.doris_helpers_faked(monkeypatch, given.an_overlap_recorder())
    spec = given.a_minimal_doris_spec()

    with cve_environments.doris_db_env("image", spec) as launch:
        env_args = launch.args
    helper = doris_server_args("server-name", "image", spec.host, DORIS_SERVER_LAUNCH)

    helper = _strip_pair(helper, "--name")
    helper = _without(helper, user_args(spec.host.user))
    helper = _strip_pair(helper, "-w")

    assert helper == _strip_pair(env_args, "--name")


def test_the_helper_adds_the_hosts_user_and_working_directory():
    spec = given.a_minimal_doris_spec()

    args = doris_server_args("server-name", "image", spec.host, DORIS_SERVER_LAUNCH)

    assert _follows(args, "--user", "65534:65534")
    assert _follows(args, "-w", "/srv")
    assert args[-len(DORIS_SERVER_LAUNCH) - 1 :] == ["image", *DORIS_SERVER_LAUNCH]
