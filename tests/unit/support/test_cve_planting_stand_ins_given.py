import json
from pathlib import Path

from evals.cve_planting import PlantingSpec
from evals.cve_planting_base import PublicNames
from tests.unit.support.test_cve_planting_given import FakePlantingDocker as FakePlantingDocker
from tests.unit.support.test_cve_planting_given import endpoint_place as endpoint_place
from tests.unit.support.test_cve_planting_given import file_place as file_place
from tests.unit.support.test_cve_planting_given import following as following
from tests.unit.support.test_cve_planting_given import only as only
from tests.unit.support.test_cve_planting_given import spec_of, unprivileged_host

HOST = "public.fict"
ADDRESS = "93.184.215.14"  # a global unicast address, as the loader requires
CERTIFICATE = "fictional leaf"
KEY = "fictional key"
AUTHORITY = "fictional authority"


def a_stand_ins_directory(directory: Path) -> Path:
    capture = {
        "host": HOST,
        "address": ADDRESS,
        "captured_at": "2026-11-02T10:00:00Z",
        "command": "uv run python -m evals.capture_stand_in --out x.json http://public.fict/",
        "request_headers": [],
        "routes": [
            {
                "scheme": "http",
                "method": "GET",
                "target": "/",
                "status": 200,
                "headers": [["Content-Type", "text/html"]],
                "body": "<html></html>",
            }
        ],
    }
    (directory / f"{HOST}.json").write_text(json.dumps(capture))
    tls = directory / "tls"
    tls.mkdir()
    (tls / f"{HOST}.pem").write_text(CERTIFICATE)
    (tls / f"{HOST}-key.pem").write_text(KEY)
    (tls / "fixture-authority.pem").write_text(AUTHORITY)
    return directory


def capture_text(directory: Path) -> str:
    return (directory / f"{HOST}.json").read_text()


def a_spec_with_the_stand_in(
    *, trust: tuple[str, ...] = (), endpoint_host: str | None = None
) -> PlantingSpec:
    places = [endpoint_place(host=endpoint_host)] if endpoint_host is not None else []
    names = PublicNames(stand_ins=(HOST,), trust=trust)
    return spec_of(places, host=unprivileged_host(has_network=True, public_names=names))


def a_spec_without_public_names() -> PlantingSpec:
    return spec_of([file_place()], host=unprivileged_host(has_network=True))
