from pathlib import Path

from evals.census_draw import CalibrationCard
from evals.cve_baseline import ENVIRONMENT_PATHS
from evals.cve_targets import CVETarget
from evals.docker_paths import image_dockerfile
from tests.unit.support.test_nuisance_fixture_sources_then import (
    host_stand_in_files,
    requests_missing_from_the_file,
    stand_in_paths_outside,
)


def every_card_stand_in_is_fingerprinted(card: CalibrationCard, target: CVETarget) -> None:
    covered = {path.resolve() for path in fingerprinted_files(target)}
    for card_stand_in in card.stand_ins or []:
        assert stand_in_paths_outside(card_stand_in.stand_in, covered) == []
        assert requests_missing_from_the_file(card_stand_in.stand_in) == []


def fingerprinted_files(target: CVETarget) -> list[Path]:
    """The files cve_baseline.fixture_fingerprint reads for the target."""
    dockerfiles = [image_dockerfile(name) for name in (*target.images, target.patched_image)]
    served = host_stand_in_files(target.planting_host)
    return [*ENVIRONMENT_PATHS, *dockerfiles, *served, *target.backend_sources]
