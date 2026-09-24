from evals.probe import Admission


def admitted(admission: Admission) -> None:
    assert admission.admitted, admission.reasons
    assert admission.reasons == []


def rejected_for(admission: Admission, *words: str) -> None:
    assert not admission.admitted
    assert any(all(word in reason for word in words) for reason in admission.reasons), (
        admission.reasons
    )
