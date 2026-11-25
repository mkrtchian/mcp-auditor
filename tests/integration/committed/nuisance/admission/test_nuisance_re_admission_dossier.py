from evals.cve.nuisance.admission.holdout_target_reference import holdout_fixture_file
from evals.cve.nuisance.admission.re_admission_dossier import copied_holdout_targets
from tests.unit.support.committed_nuisance_admission import (
    the_committed_admission,
    the_copy_resolution,
)


def test_every_copied_flaw_resolves_to_one_target_and_one_fixture():
    resolution = the_copy_resolution()
    for server in the_committed_admission().servers:
        calibrated = {
            flaw.flaw
            for flaw in server.flaws
            if flaw.fix_check.source == "detection_holdout_calibration"
        }
        assert calibrated <= resolution.keys(), server.server_package
        targets = copied_holdout_targets(server, resolution)
        assert {target.flaw_id for target in targets} == {
            resolution[flaw] for flaw in calibrated
        }, server.server_package
        for target in targets:
            assert holdout_fixture_file(target.flaw_id).is_file()
