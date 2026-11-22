import importlib

from evals.cve.backends import gitlab_responder
from evals.cve.backends.responder import Responder
from evals.cve.nuisance.backend_registry import BACKENDS


def every_responder() -> list[Responder]:
    # The GitLab responder serves a fix check, not a registered backend.
    names = [*(f"evals.cve.backends.{key}" for key in BACKENDS), gitlab_responder.__name__]
    modules = (importlib.import_module(name) for name in names)
    return [
        value
        for module in modules
        for value in vars(module).values()
        if isinstance(value, Responder)
    ]
