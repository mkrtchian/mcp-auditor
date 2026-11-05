from pathlib import Path

import tests.unit.support.test_census_draw_given as draw_given
import tests.unit.support.test_holdout_census_given as census_given
import tests.unit.support.test_nuisance_admission_given as admission_given
import tests.unit.support.test_nuisance_admission_records_given as records_given
import tests.unit.support.test_nuisance_walk_given as walk_given

QUEUE_FLAW = "CVE-2025-7777"
QUEUE_SERVER = "npm:queued"


def a_walk_with_a_queue_server(
    tmp_path: Path, admitted: bool, queue_server_unrecorded: bool = False
) -> list[str]:
    """The census and walk record arguments of a walk whose holdout part reaches
    `npm:@acme/files` and whose queue reaches QUEUE_SERVER through QUEUE_FLAW, with the admission
    of both servers when `admitted`, else a missing admission path. QUEUE_SERVER's admission
    predates the fields rule v3 adds when `queue_server_unrecorded`."""
    census = draw_given.with_a_walk_skipping(
        census_given.with_a_cve_of(census_given.a_census(), QUEUE_FLAW, QUEUE_SERVER),
        admission_given.FIRST_FLAW,
    )
    admission_path = tmp_path / "absent.json"
    if admitted:
        admission = admission_given.an_admission()
        queued = admission_given.admitting_the_server_of(
            QUEUE_FLAW, QUEUE_SERVER, "queued-nuisance"
        )
        if queue_server_unrecorded:
            queued = records_given.with_every_new_field_unrecorded(queued)
        both = admission.model_copy(update={"servers": [*admission.servers, *queued.servers]})
        admission_path = admission_given.written(tmp_path, both)
    return [
        *walk_given.committed_census_arguments(tmp_path, census_given.written(tmp_path, census)),
        "--admission",
        str(admission_path),
    ]
