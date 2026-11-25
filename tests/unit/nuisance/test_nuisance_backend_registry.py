import tests.unit.support.admission_mutations as mutations
import tests.unit.support.nuisance_admissions as admissions
from evals.cve.nuisance.backend_registry import backend_problems


def test_a_recorded_backend_whose_image_list_differs_from_the_registered_one_is_refused():
    fixture = admissions.a_registered_backend_fixture()
    recorded = fixture.model_copy(update={"images": [*fixture.images, "fake/extra:1.0"]})
    server = mutations.with_a_backend(admissions.an_admitted_server(), recorded)

    problems = backend_problems(server, admissions.a_backend_registry())

    assert len(problems) == 1
    assert "is not the registered" in problems[0]
