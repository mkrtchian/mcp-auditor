import tests.unit.nuisance.admission.support.test_nuisance_admission_given as admission_given
import tests.unit.support.admission_mutations as mutations
from evals.cve.nuisance.admission.admission import BackendFixture
from evals.cve.nuisance.backend_registry import backend_problems


def test_a_recorded_backend_whose_image_list_differs_from_the_registered_one_is_refused():
    recorded = BackendFixture(
        provisioner="fake", images=["fake/backend:1.0", "fake/extra:1.0"], network="fake-net"
    )
    server = mutations.with_a_backend(admission_given.an_admitted_server(), recorded)

    problems = backend_problems(server, admission_given.a_backend_registry())

    assert len(problems) == 1
    assert "is not the registered" in problems[0]
