# The Docker adapter: what the host tells us about the `docker` client, and the I/O
# with the daemon.
from collections.abc import Mapping

_CLIENT_VARIABLES = (
    "DOCKER_HOST",
    "DOCKER_CONTEXT",
    "DOCKER_CONFIG",
    "DOCKER_TLS_VERIFY",
    "DOCKER_CERT_PATH",
)


def docker_client_env(environ: Mapping[str, str]) -> dict[str, str]:
    """The environment of the host-side `docker` client process, not of the container.

    The MCP SDK passes only HOME, LOGNAME, PATH, SHELL, TERM and USER to the process it
    spawns, so a rootless DOCKER_HOST would be answered by the availability check and
    then lost at launch, sending the run to the default socket.
    """
    return {name: environ[name] for name in _CLIENT_VARIABLES if name in environ}
