from evals.cve.detection.baseline import fingerprinted_files
from evals.cve.detection.draw_record import CalibrationCard
from evals.cve.detection.targets import Target
from evals.cve.docker_paths import image_dockerfile
from evals.cve.fixture_sources import (
    unfingerprinted_stand_in_files,
    unheld_requests,
    unserved_captures,
)
from evals.cve.places import DETECTION_PLACES, load_places
from evals.repository import REPO_ROOT

_STAND_IN_DOCKERFILE = image_dockerfile("stand-in")


def every_card_stand_in_is_fingerprinted(card: CalibrationCard, target: Target) -> None:
    covered = fingerprinted_files(target, load_places(DETECTION_PLACES))
    for card_stand_in in card.stand_ins:
        assert unfingerprinted_stand_in_files(card_stand_in.stand_in, covered, REPO_ROOT) == []
        assert unheld_requests(card_stand_in.stand_in, REPO_ROOT) == []
        assert unserved_captures(card_stand_in.stand_in, _STAND_IN_DOCKERFILE, REPO_ROOT) == []
