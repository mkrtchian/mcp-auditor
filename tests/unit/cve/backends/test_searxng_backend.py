import pytest

import tests.unit.cve.backends.support.test_searxng_backend_given as given
from evals.cve.backends.searxng import SEARXNG_IMAGE
from tests.fakes.planting_docker import FakePlantingDocker
from tests.unit.cve.backends.support.fixture_authority import trusts_the_fixture_authority
from tests.unit.support.docker_argv import carries, environment, value_after


def test_searxng_and_the_server_join_the_launchs_holder():
    planting = FakePlantingDocker()
    searxng = given.FakeSearxng(planting)

    with given.a_launch(planting, searxng) as launch:
        [holder] = planting.holders
        [started] = searxng.started
        assert value_after(started, "--network") == f"container:{holder}"
        assert value_after(launch.args, "--network") == f"container:{holder}"


def test_searxng_runs_under_its_own_account_with_no_capability():
    planting = FakePlantingDocker()
    searxng = given.FakeSearxng(planting)

    with given.a_launch(planting, searxng):
        [started] = searxng.started
        assert value_after(started, "--user") == "searxng"
        assert carries(started, ["--cap-drop", "ALL"])
        assert carries(started, ["--security-opt", "no-new-privileges"])
        assert "--cap-add" not in started
        assert started[-1] == SEARXNG_IMAGE


def test_searxng_trusts_the_fixture_authority_through_its_http_clients_variable():
    planting = FakePlantingDocker()
    searxng = given.FakeSearxng(planting)

    with given.a_launch(planting, searxng):
        [started] = searxng.started
        trusts_the_fixture_authority(started, "SSL_CERT_FILE", "html.duckduckgo.com")


def test_the_server_reaches_searxng_at_the_address_of_the_readme_example():
    planting = FakePlantingDocker()
    searxng = given.FakeSearxng(planting)

    with given.a_launch(planting, searxng) as launch:
        assert environment(launch.args)["SEARXNG_URL"] == "http://localhost:8080"
        assert launch.args[-1] == "img"


def test_searxng_answers_before_the_server_launches():
    planting = FakePlantingDocker()
    searxng = given.FakeSearxng(planting)

    with given.a_launch(planting, searxng):
        [started] = searxng.started
        assert searxng.awaited == [value_after(started, "--name")]


def test_searxng_is_removed_before_the_holder_even_when_the_launch_raises():
    planting = FakePlantingDocker()
    searxng = given.FakeSearxng(planting)

    with pytest.raises(RuntimeError, match="audit failed"), given.a_launch(planting, searxng):
        raise RuntimeError("audit failed")

    [started] = searxng.started
    assert searxng.removed == [value_after(started, "--name")]
    assert [len(holders) for holders in searxng.holders_at_removal] == [1]
    assert planting.holders == {}


def test_a_searxng_that_never_answers_is_removed_and_no_server_launches():
    planting = FakePlantingDocker()
    searxng = given.a_searxng_that_never_answers(planting)

    with pytest.raises(RuntimeError, match="never answered"), given.a_launch(planting, searxng):
        pytest.fail("the server launched")

    [started] = searxng.started
    assert searxng.removed == [value_after(started, "--name")]
    assert planting.holders == {}
