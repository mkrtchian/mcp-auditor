from dataclasses import replace
from pathlib import Path

import pytest

import tests.unit.support.test_nuisance_admission_given as admission_given
from evals.cve.nuisance import fingerprint as nuisance_fingerprint
from evals.cve.nuisance.backend_registry import RegisteredBackend
from evals.cve_grammar import MechanismClass
from evals.cve_planting_base import SENTINEL_SERVICE, STAND_IN_SERVICE, PublicNames
from evals.nuisance_admission import AdmittedServer

SERVICE = admission_given.a_server([]).service
SERVED_CHANGES = [
    ("Dockerfile.fake-responder", "FROM python:3.13\n", "FROM python:3.14\n"),
    ("fake_backend.py", "ANSWER = 1\n", "ANSWER = 2\n"),
    ("capture.json", '{"body": "one"}', '{"body": "two"}'),
]


def written_dockerfile(directory: Path, text: str = "FROM node:22\nRUN npm install demo\n") -> Path:
    dockerfile = directory / f"Dockerfile.{SERVICE}"
    dockerfile.write_text(text)
    return dockerfile


def a_registry_serving(directory: Path) -> dict[str, RegisteredBackend]:
    """The fake backend serving the files of SERVED_CHANGES, written in their first state."""
    for name, before, _ in SERVED_CHANGES:
        (directory / name).write_text(before)
    served = tuple(directory / name for name, _, _ in SERVED_CHANGES)
    return {"fake": replace(admission_given.a_backend_registry()["fake"], served=served)}


def a_confinement_copy(directory: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """A copy of the confinement source the fingerprint reads in place of the real one."""
    copy = directory / "nuisance_confinement.py"
    copy.write_text(nuisance_fingerprint.CONFINEMENT_SOURCE.read_text())
    monkeypatch.setattr(nuisance_fingerprint, "CONFINEMENT_SOURCE", copy)
    return copy


def one_flaw_server(effect_class: MechanismClass) -> AdmittedServer:
    flaw = admission_given.a_flaw_record(
        admission_given.FIRST_FLAW, effect_class, admission_given.PATCHED_VERSION
    )
    return admission_given.a_server([flaw])


def written_public_name_dockerfiles(
    directory: Path, stand_in: str = "FROM python:3.12\nRUN true\n"
) -> None:
    (directory / f"Dockerfile.{SENTINEL_SERVICE}").write_text("FROM busybox:1.37\n")
    (directory / f"Dockerfile.{STAND_IN_SERVICE}").write_text(stand_in)


def serving_a_public_name(server: AdmittedServer) -> AdmittedServer:
    names = PublicNames(stand_ins=("example.com",))
    return admission_given.with_host(server, replace(server.host, public_names=names))
