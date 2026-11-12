from typing import Literal

import tests.unit.support.test_detection_draw_record_given as draw_given
import tests.unit.support.test_nuisance_admission_edits_given as edits
import tests.unit.support.test_nuisance_admission_given as admission_given
from evals.cve.detection.draw_record import CalibrationCard, DrawRecord, Sibling
from evals.cve.nuisance.admission import AdmittedServer, FlawRecord

SERVER = admission_given.SERVER_PACKAGE
COPIED_FLAW = admission_given.FIRST_FLAW
RECORDED = "a" * 64

DRAWN = "CVE-2030-0001"
SIBLING = "CVE-2030-0002"
NOT_DRAWN = "CVE-2030-0100"
ITS_SIBLING = "CVE-2030-0101"


def a_draw_whose_card_lists(flaw: str, sibling: str) -> DrawRecord:
    return draw_given.a_draw_carrying(_a_card_listing(flaw, sibling))


def _a_card_listing(flaw: str, sibling: str) -> CalibrationCard:
    sibling_record = Sibling(flaw=sibling, mechanism="a path argument", reach="a tool call")
    return draw_given.a_card(flaw).model_copy(update={"siblings": [sibling_record]})


def a_server_with_a_holdout_calibration_copy_at(
    fingerprint: str | None,
    source: Literal["fix_check", "detection_holdout_calibration"] = "detection_holdout_calibration",
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
