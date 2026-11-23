from dataclasses import replace
from pathlib import Path

import tests.unit.support.admission_mutations as mutations
import tests.unit.support.fictional_stand_ins as fictional_stand_ins
import tests.unit.support.nuisance_admissions as admissions
from evals.cve.fixture_provenance import StandInRecord
from evals.cve.grammar import FlawClass
from evals.cve.nuisance.admission.admission import AdmissionSettlement, AdmittedServer
from evals.cve.nuisance.admission.admission_records import SeedRecord
from evals.cve.nuisance.backend_registry import RegisteredBackend
from evals.cve.nuisance.fingerprint import CONFINEMENT_SOURCE
from evals.cve.planting_base import SENTINEL_SERVICE, STAND_IN_SERVICE, PublicNames

SERVICE = admissions.a_server([]).service
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
    return {"fake": replace(admissions.a_backend_registry()["fake"], served=served)}


def a_confinement_copy(directory: Path) -> Path:
    copy = directory / "confinement.py"
    copy.write_text(CONFINEMENT_SOURCE.read_text())
    return copy


def one_flaw_server(effect_class: FlawClass) -> AdmittedServer:
    flaw = admissions.a_flaw_record(admissions.FIRST_FLAW, effect_class, admissions.PATCHED_VERSION)
    return admissions.a_server([flaw])


def written_public_name_dockerfiles(
    directory: Path, stand_in: str = "FROM python:3.12\nRUN true\n"
) -> None:
    (directory / f"Dockerfile.{SENTINEL_SERVICE}").write_text("FROM busybox:1.37\n")
    (directory / f"Dockerfile.{STAND_IN_SERVICE}").write_text(stand_in)


def serving_a_public_name(server: AdmittedServer) -> AdmittedServer:
    names = PublicNames(stand_ins=(fictional_stand_ins.HOST,))
    return mutations.with_host(server, replace(server.host, public_names=names))


def with_provenance_records(server: AdmittedServer) -> AdmittedServer:
    seed = SeedRecord(item="/agents.yaml", kind="written")
    stand_in = StandInRecord(
        replaces="api.example.com",
        reason="no network",
        file="evals/docker/Dockerfile.x",
        capture="evals/stand_ins/api.example.com.json",
        outputs=[],
    )
    return server.model_copy(update={"seeds": [seed], "stand_ins": [stand_in]})


def with_a_moved_exploit_and_a_settlement(server: AdmittedServer) -> AdmittedServer:
    moved_exploit = mutations.with_the_first_flaw(
        server,
        lambda flaw: flaw.model_copy(
            update={
                "fix_check": flaw.fix_check.model_copy(update={"exploit_calls": ["other_tool"]})
            }
        ),
    )
    settled = AdmissionSettlement(
        server_package=server.server_package,
        flaw=None,
        field="runs_under_docker",
        value="true",
        reason="a different reason",
    )
    return moved_exploit.model_copy(update={"settlements": [settled]})
