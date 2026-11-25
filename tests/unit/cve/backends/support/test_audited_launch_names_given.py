from evals.cve.backends.facebook_ads import FACEBOOK_ADS_RESPONDER
from evals.cve.backends.lifecycle import BackendLifecycle, PerLaunchBackend, launched_server_args
from evals.cve.nuisance.backend_registry import BACKENDS
from evals.cve.planting_base import PlantingHost, SymbolicUser
from tests.unit.cve.backends.support.quiet_backends import a_lifecycle_without_side_effects

SERVER = "server-name"
_IMAGE = "img"
_HOST = PlantingHost(SymbolicUser.UNPRIVILEGED, "/", has_network=True)
_LAUNCH = ("serve",)


def named_run_args() -> dict[str, list[str]]:
    """The run argv of a nuisance server named SERVER beside each registered backend, stood with
    no container, and beside a responder."""
    return {
        **{key: _beside(a_lifecycle_without_side_effects(key)) for key in sorted(BACKENDS)},
        "Responder.server_args": FACEBOOK_ADS_RESPONDER.server_args(SERVER, _IMAGE, _HOST, _LAUNCH),
    }


def _beside(lifecycle: BackendLifecycle | PerLaunchBackend) -> list[str]:
    with launched_server_args(lifecycle)(SERVER, _IMAGE, _HOST, _LAUNCH) as args:
        return args
