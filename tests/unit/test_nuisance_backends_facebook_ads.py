import tests.unit.support.test_nuisance_admission_given as given
from evals.facebook_ads_backend import FACEBOOK_ADS_BRIDGE, FACEBOOK_ADS_RESPONDER_IMAGE
from evals.nuisance_admission import AdmittedServer, BackendFixture
from evals.nuisance_backends import BACKENDS, backend_problems


def _a_server() -> AdmittedServer:
    return given.an_admission().servers[0]


def test_the_facebook_ads_fixture_is_accepted_by_the_registry():
    backend = BackendFixture(
        provisioner="facebook_ads",
        image=FACEBOOK_ADS_RESPONDER_IMAGE,
        network=FACEBOOK_ADS_BRIDGE,
    )

    assert backend_problems(given.with_a_backend(_a_server(), backend), BACKENDS) == []
