import pytest

import tests.unit.support.test_workflow_path_filters_given as given


def test_the_detection_calibration_check_workflow_filters_on_paths():
    assert given.path_filters(given.REPO_ROOT / ".github/workflows/detection-calibration-check.yml")


# A filter left on a moved path matches nothing, and the job stops triggering silently.
@pytest.mark.parametrize(
    ("workflow", "event", "pattern"),
    given.every_path_filter(),
    ids=lambda value: str(value),
)
def test_every_path_filter_matches_a_tracked_file(workflow: str, event: str, pattern: str):
    assert given.matches_a_tracked_file(pattern), f"{workflow} {event}: {pattern} matches no file"
