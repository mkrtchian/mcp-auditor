import pytest

import tests.unit.support.test_cve_planting_given as given
from evals.cve_places import LayoutAnchor
from evals.cve_planting import RANDOM_NONCES, planting_spec
from evals.cve_planting_base import LayoutNode
from evals.cve_planting_spec import URL_SAFE_USERINFO


def test_a_git_remote_url_place_records_a_project_bare_config_node_with_the_nonce():
    spec = given.spec_of([given.git_remote_url_place()])

    assert spec.layout == (
        LayoutNode(LayoutAnchor.PROJECT_BARE, "config", spec.nonces["bare-remote-url-fic"]),
    )


def test_a_git_history_place_records_a_project_bare_env_node_with_the_nonce():
    spec = given.spec_of([given.git_history_place()])

    assert spec.layout == (
        LayoutNode(LayoutAnchor.PROJECT_BARE, ".env", spec.nonces["bare-history-fic"]),
    )


def test_a_dotenv_place_records_a_workspace_env_node_with_the_nonce():
    spec = given.spec_of([given.dotenv_place()])

    assert spec.layout == (
        LayoutNode(LayoutAnchor.WORKSPACE, ".env", spec.nonces["ws-dotenv-fic"]),
    )


def test_every_layout_place_carries_through_finish_in_order():
    spec = given.spec_of(
        [given.git_remote_url_place(), given.git_history_place(), given.dotenv_place()]
    )

    assert [(node.anchor, node.relpath) for node in spec.layout] == [
        (LayoutAnchor.PROJECT_BARE, "config"),
        (LayoutAnchor.PROJECT_BARE, ".env"),
        (LayoutAnchor.WORKSPACE, ".env"),
    ]


def test_a_spec_with_no_kept_layout_place_carries_an_empty_layout():
    spec = given.spec_of([given.file_place(path="/etc/x"), given.env_place()])

    assert spec.layout == ()


def test_the_production_token_is_url_safe_for_a_remote_url_userinfo():
    assert URL_SAFE_USERINFO.fullmatch(RANDOM_NONCES.token())


@pytest.mark.parametrize("token", ["needs@encoding", "needs:encoding", "needs/encoding"])
def test_a_git_remote_url_nonce_that_is_not_url_safe_raises_naming_the_id_not_the_value(token: str):
    with pytest.raises(ValueError) as caught:
        planting_spec(
            [given.git_remote_url_place()], given.unprivileged_host(), given.FixedTokenNonces(token)
        )

    assert "bare-remote-url-fic" in str(caught.value)
    assert token not in str(caught.value)
