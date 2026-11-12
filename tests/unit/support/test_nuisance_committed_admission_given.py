from functools import cache

from evals.cve.census.census import load_census
from evals.cve.detection.baseline import fixture_fingerprint
from evals.cve.detection.holdout_targets import HOLDOUT_TARGETS
from evals.cve.nuisance.admission import ADMISSION_PATH, NuisanceAdmission, load_admission
from evals.cve.nuisance.commands import CENSUS_PATH, WALK_RECORD_PATH
from evals.cve.nuisance.holdout_calibration_copies import copy_targets
from evals.cve.nuisance.walk_record import WalkInputs, load_walk_record
from evals.cve.places import DETECTION_PLACES, load_places


@cache
def the_committed_census() -> WalkInputs:
    return load_walk_record(WALK_RECORD_PATH, load_census(CENSUS_PATH))


@cache
def the_committed_admission() -> NuisanceAdmission:
    return load_admission(ADMISSION_PATH, the_committed_census())


def current_copy_fingerprints() -> dict[str, str]:
    """Each copyable flaw's current fingerprint: the fixture fingerprint of the drawn target its
    copy resolves to, as the nuisance run reads it."""
    places = load_places(DETECTION_PLACES)
    fingerprints = {t.flaw_id: fixture_fingerprint(t, places) for t in HOLDOUT_TARGETS}
    drawn = [target.flaw_id for target in HOLDOUT_TARGETS]
    resolution = copy_targets(drawn, the_committed_census().census.draw)
    return {copy: fingerprints[target] for copy, target in resolution.items()}
