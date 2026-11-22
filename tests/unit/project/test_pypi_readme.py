import pytest

import tests.unit.project.support.test_pypi_readme_given as given


@pytest.fixture(scope="module")
def rendering(tmp_path_factory: pytest.TempPathFactory) -> str:
    directory = tmp_path_factory.mktemp("pypi_readme")
    return given.rendered(given.a_project_with_readme(directory, given.LINK_KINDS_README))


def test_a_relative_image_is_served_raw_from_the_release_tag(rendering: str):
    assert (
        "https://raw.githubusercontent.com/mkrtchian/mcp-auditor/v42.0/docs/demo/demo.gif"
        in given.link_targets(rendering)
    )


def test_an_in_page_anchor_is_left_as_written(rendering: str):
    assert "#measurement" in given.link_targets(rendering)


def test_a_directory_link_points_at_the_tree_of_the_release_tag(rendering: str):
    assert (
        "https://github.com/mkrtchian/mcp-auditor/tree/v42.0/evals/cve/holdout_runs/"
        in given.link_targets(rendering)
    )


def test_a_file_link_keeps_its_anchor_on_the_release_tag(rendering: str):
    assert (
        "https://github.com/mkrtchian/mcp-auditor/blob/v42.0/docs/usage.md#confinement"
        in given.link_targets(rendering)
    )


def test_absolute_links_and_badges_are_left_as_written(rendering: str):
    targets = given.link_targets(rendering)

    assert "https://img.shields.io/pypi/v/mcp-auditor" in targets
    assert "https://pypi.org/project/mcp-auditor/" in targets
    assert "https://github.com/mkrtchian/mcp-auditor" in targets


def test_the_rendering_changes_nothing_but_link_targets(rendering: str):
    assert (
        given.without_link_targets(rendering).rstrip()
        == given.without_link_targets(given.LINK_KINDS_README).rstrip()
    )
