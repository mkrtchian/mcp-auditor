from evals.cve.backends.httpbin import HTTPBIN_PARTS, HttpbinPart
from evals.cve.planting_base import PlantingHost, SymbolicUser


def a_host() -> PlantingHost:
    return PlantingHost(SymbolicUser.UNPRIVILEGED, "/tmp", has_network=True)


def the_front() -> HttpbinPart:
    return next(part for part in HTTPBIN_PARTS if part.service == "httpbin-front")
