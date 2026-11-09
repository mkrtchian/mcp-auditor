from evals.atlassian_backend import atlassian_env_args
from tests.unit.support.docker_argv import environment


def test_the_environment_points_at_the_responder_address_it_is_given():
    variables = environment(atlassian_env_args("198.18.0.77"))

    assert variables["JIRA_URL"] == "http://198.18.0.77"
    assert variables["CONFLUENCE_URL"] == "http://198.18.0.77"


def test_both_clients_are_scoped_to_the_project_and_space_of_the_server_examples():
    variables = environment(atlassian_env_args("198.18.0.77"))

    assert variables["JIRA_PROJECTS_FILTER"] == "PROJ"
    assert variables["CONFLUENCE_SPACES_FILTER"] == "TEAM"
