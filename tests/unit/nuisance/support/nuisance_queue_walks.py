from pathlib import Path

import tests.unit.support.admission_mutations as mutations
import tests.unit.support.nuisance_admissions as admissions
import tests.unit.support.nuisance_walks as walks
from tests.unit.support import census_draws, censuses

QUEUE_FLAW = "CVE-2025-7777"
QUEUE_SERVER = "npm:queued"


def a_walk_with_a_queue_server(
    tmp_path: Path, admitted: bool, queue_server_unrecorded: bool = False
) -> list[str]:
    """The census and walk record arguments of a walk whose holdout part reaches
    `npm:@acme/files` and whose queue reaches QUEUE_SERVER through QUEUE_FLAW, with the admission
    of both servers when `admitted`, else a missing admission path. QUEUE_SERVER's admission
    predates the fields nuisance suite rule v3 adds when `queue_server_unrecorded`."""
    census = census_draws.with_a_walk_skipping(
        censuses.with_a_classified_flaw(censuses.a_census(), QUEUE_FLAW, QUEUE_SERVER),
        admissions.FIRST_FLAW,
    )
    admission_path = tmp_path / "absent.json"
    if admitted:
        admission = admissions.an_admission()
        queued = admissions.admitting_the_server_of(QUEUE_FLAW, QUEUE_SERVER, "queued-nuisance")
        if queue_server_unrecorded:
            queued = mutations.with_every_new_field_unrecorded(queued)
        both = admission.model_copy(update={"servers": [*admission.servers, *queued.servers]})
        admission_path = admissions.written(tmp_path, both)
    return [
        *walks.committed_census_arguments(tmp_path, censuses.written(tmp_path, census)),
        "--admission",
        str(admission_path),
    ]
