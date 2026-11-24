from pathlib import Path

import tests.unit.support.nuisance_admissions as admissions
import tests.unit.support.nuisance_walks as walks
from evals.cve.nuisance.admission.walk_record import IdentitySettlement
from tests.unit.nuisance.support.nuisance_queue_walks import QUEUE_FLAW
from tests.unit.support import census_draws, censuses


def a_walk_reaching_an_excluded_server(tmp_path: Path) -> list[str]:
    """The `walk` arguments of a census whose queue reaches AN_EXCLUDED_SERVER through QUEUE_FLAW,
    the two classifiers naming different packages and the walk record settling the identity on
    the excluded one, with a missing admission path."""
    with_the_flaw = censuses.with_a_cve_of(
        censuses.a_census(), QUEUE_FLAW, walks.AN_EXCLUDED_SERVER
    )
    disagreeing = censuses.recomputed(
        walks.with_the_second_classifier_overriding(
            with_the_flaw, QUEUE_FLAW, {"server_package": "npm:another-label"}
        )
    )
    census = census_draws.with_a_walk_skipping(disagreeing, admissions.FIRST_FLAW)
    identity = IdentitySettlement(
        flaw=QUEUE_FLAW, server_package=walks.AN_EXCLUDED_SERVER, reason="one project"
    )
    record = walks.an_empty_record().model_copy(update={"identities": [identity]})
    return [
        "--census",
        str(censuses.written(tmp_path, census)),
        "--walk-record",
        str(walks.written_record(tmp_path, record)),
        "--admission",
        str(tmp_path / "absent.json"),
    ]
