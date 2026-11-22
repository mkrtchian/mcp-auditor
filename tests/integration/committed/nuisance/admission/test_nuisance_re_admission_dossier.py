from evals.cve.nuisance.admission.holdout_target_reference import holdout_fixture_file
from evals.cve.nuisance.admission.re_admission_dossier import (
    fix_check_modules,
    holdout_target_references,
)
from tests.integration.committed.nuisance.admission.support import (
    test_nuisance_re_admission_dossier_given as given,
)
from tests.unit.nuisance.admission.support import (
    test_nuisance_re_admission_dossier_given as re_admission,
)
from tests.unit.support.test_nuisance_committed_admission_given import the_committed_admission


def test_no_committed_server_carries_a_shared_helper_of_the_fix_check_package():
    helpers = set(given.the_fix_check_package_helpers())

    for server in the_committed_admission().servers:
        assert helpers.isdisjoint(fix_check_modules(server)), server.server_package


def test_every_copied_flaw_resolves_to_one_target_and_one_fixture():
    resolution = re_admission.the_copy_resolution()
    for server in the_committed_admission().servers:
        calibrated = {
            flaw.flaw
            for flaw in server.flaws
            if flaw.fix_check.source == "detection_holdout_calibration"
        }
        assert calibrated <= resolution.keys(), server.server_package
        targets = holdout_target_references(server, resolution)
        assert {target.flaw_id for target in targets} == {
            resolution[flaw] for flaw in calibrated
        }, server.server_package
        for target in targets:
            assert holdout_fixture_file(target.flaw_id).is_file()
