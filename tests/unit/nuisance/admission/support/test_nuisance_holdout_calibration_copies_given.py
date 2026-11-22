import tests.unit.support.admission_mutations as mutations
import tests.unit.support.nuisance_admissions as admissions
from evals.cve.detection.draw_record import CalibrationCard, DrawRecord, Sibling
from evals.cve.nuisance.admission.admission import AdmittedServer, FlawRecord
from tests.unit.support import census_draws

SERVER = admissions.SERVER_PACKAGE
COPIED_FLAW = admissions.FIRST_FLAW
RECORDED = "a" * 64

DRAWN = "CVE-2030-0001"
SIBLING = "CVE-2030-0002"
NOT_DRAWN = "CVE-2030-0100"
ITS_SIBLING = "CVE-2030-0101"


def a_draw_whose_card_lists(flaw: str, sibling: str) -> DrawRecord:
    return census_draws.a_draw_carrying(_a_card_listing(flaw, sibling))


def _a_card_listing(flaw: str, sibling: str) -> CalibrationCard:
    sibling_record = Sibling(flaw=sibling, mechanism="a path argument", reach="a tool call")
    return census_draws.a_card(flaw).model_copy(update={"siblings": [sibling_record]})


def not_counting(server: AdmittedServer) -> AdmittedServer:
    def uncounted(flaw: FlawRecord) -> FlawRecord:
        check = flaw.fix_check.model_copy(update={"vulnerable_surfaces": False})
        return flaw.model_copy(update={"fix_check": check})

    return mutations.with_the_first_flaw(server, uncounted)
