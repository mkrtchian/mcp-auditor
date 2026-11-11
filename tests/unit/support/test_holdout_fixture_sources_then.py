from pathlib import Path

from evals.cve.detection.draw_record import CalibrationCard
from evals.cve_baseline import ENVIRONMENT_PATHS, host_stand_in_files
from evals.cve_places import HOLDOUT_PLACES, PlantKind, kept_records, load_places
from evals.cve_targets import CVETarget
from evals.docker_paths import image_dockerfile
from evals.fixture_sources import (
    unfingerprinted_stand_in_files,
    unheld_requests,
    unreplayed_captures,
)
from evals.honeypots import REPO_ROOT

_REPLAYER = image_dockerfile("stand-in")


def every_card_stand_in_is_fingerprinted(card: CalibrationCard, target: CVETarget) -> None:
    covered = _fingerprinted_files(target)
    for card_stand_in in card.stand_ins:
        assert unfingerprinted_stand_in_files(card_stand_in.stand_in, covered, REPO_ROOT) == []
        assert unheld_requests(card_stand_in.stand_in, REPO_ROOT) == []
        assert unreplayed_captures(card_stand_in.stand_in, _REPLAYER, REPO_ROOT) == []


def _fingerprinted_files(target: CVETarget) -> list[Path]:
    """The files cve_baseline.fixture_fingerprint reads for the target."""
    names = [*target.images, target.patched_image]
    records = kept_records(target.kept_places, load_places(HOLDOUT_PLACES))
    if any(record.kind is PlantKind.HTTP_ENDPOINT for record in records):
        names.append("sentinel")
    dockerfiles = [image_dockerfile(name) for name in names]
    served = host_stand_in_files(target.planting_host)
    return [*ENVIRONMENT_PATHS, *dockerfiles, *served, *target.backend_sources]
