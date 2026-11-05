from typing import Literal

import tests.unit.support.test_nuisance_admission_edits_given as edits
import tests.unit.support.test_nuisance_admission_given as admission_given
from evals.nuisance_admission import AdmittedServer, FlawRecord

SERVER = admission_given.SERVER_PACKAGE
COPIED_FLAW = admission_given.FIRST_FLAW
RECORDED = "a" * 64


def a_server_copying_the_holdout_calibration_at(
    fingerprint: str | None,
    source: Literal["fix_check", "holdout_calibration"] = "holdout_calibration",
) -> AdmittedServer:
    """The admission's server whose COPIED_FLAW record carries `fingerprint` under `source`."""

    def copied(flaw: FlawRecord) -> FlawRecord:
        check = flaw.fix_check.model_copy(
            update={"source": source, "holdout_fingerprint": fingerprint}
        )
        return flaw.model_copy(update={"fix_check": check})

    return edits.with_the_first_flaw(admission_given.an_admitted_server(), copied)


def not_counting(server: AdmittedServer) -> AdmittedServer:
    def uncounted(flaw: FlawRecord) -> FlawRecord:
        check = flaw.fix_check.model_copy(update={"vulnerable_surfaces": False})
        return flaw.model_copy(update={"fix_check": check})

    return edits.with_the_first_flaw(server, uncounted)
