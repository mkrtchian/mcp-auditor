import tests.unit.project.support.test_pypi_readme_given as given
from evals.honeypots import REPO_ROOT


def test_every_link_of_the_real_readme_is_absolute_on_pypi():
    targets = given.link_targets(given.rendered(REPO_ROOT))

    assert [target for target in targets if not target.startswith(("https://", "#"))] == []
