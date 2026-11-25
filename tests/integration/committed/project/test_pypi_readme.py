from evals.repository import REPO_ROOT
from tests.unit.project.support.pypi_readme_rendering import link_targets, rendered


def test_every_link_of_the_real_readme_is_absolute_on_pypi():
    targets = link_targets(rendered(REPO_ROOT))

    assert [target for target in targets if not target.startswith(("https://", "#"))] == []
