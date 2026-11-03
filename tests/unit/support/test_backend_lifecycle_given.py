import importlib

from evals.backend_lifecycle import BackendLifecycle
from evals.cve_planting_base import PlantingHost, SymbolicUser
from evals.nuisance_backends import BACKENDS
from evals.responder_backend import Responder


def a_lifecycle(key: str) -> BackendLifecycle:
    return importlib.import_module(f"evals.{key}_backend").LIFECYCLE


def a_host() -> PlantingHost:
    return PlantingHost(SymbolicUser.UNPRIVILEGED, "/srv", has_network=False)


def every_responder() -> list[Responder]:
    modules = (importlib.import_module(f"evals.{key}_backend") for key in BACKENDS)
    return [
        value
        for module in modules
        for value in vars(module).values()
        if isinstance(value, Responder)
    ]
