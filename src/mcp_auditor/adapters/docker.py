# The Docker adapter: what the host tells us about the `docker` client, and the I/O
# with the daemon.
import logging
import subprocess
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


class DockerRuntime:
    """The container runtime the confined regime drives, one `docker` call per method."""

    def available(self) -> bool:
        return _docker("version", "--format", "{{.Server.Version}}").returncode == 0

    def endpoint(self) -> str:
        """The endpoint the client will talk to, whatever selected it.

        Reading DOCKER_HOST alone would miss a remote context selected by
        `docker context use` and no variable at all.
        """
        return _docker(
            "context", "inspect", "--format", "{{.Endpoints.docker.Host}}"
        ).stdout.strip()

    def ensure_image(self, image: str) -> str | None:
        """Pull the image when it is absent, then read its repository digest.

        `None` when the image has no repository digest, which is the normal case for
        one the user built locally: that must not stop the launch.
        """
        if _docker("image", "inspect", image).returncode != 0:
            pull = _docker("pull", image)
            if pull.returncode != 0:
                raise DockerError(pull.stderr.strip() or pull.stdout.strip())
        return _repo_digest(image)

    def pids_limit_enforced(self) -> bool | None:
        """`None` when the answer cannot be read, which is not the same as a denial.

        A CLI answering the `docker` name without the field, podman's shim among them,
        fails the template rather than reporting an absent limit. Reading that as "not
        enforced" would warn about a bound such a host does apply. The caller warns on
        `False` alone: "could not tell" gives the user nothing to act on, and on such a
        host it would fire on every run, beside the one warning that does.
        """
        answer = _docker("info", "--format", "{{.PidsLimit}}")
        return answer.stdout.strip() == "true" if answer.returncode == 0 else None

    def oom_killed(self, container_name: str) -> bool | None:
        state = _docker("inspect", "--format", "{{.State.OOMKilled}}", container_name)
        if state.returncode != 0:
            return None
        return state.stdout.strip() == "true"

    def remove(self, container_name: str) -> None:
        removal = _docker("rm", "-f", container_name)
        if removal.returncode != 0:
            logging.getLogger(__name__).warning(
                "could not remove container %s: %s", container_name, removal.stderr.strip()
            )


def _repo_digest(image: str) -> str | None:
    inspection = _docker("image", "inspect", "--format", "{{index .RepoDigests 0}}", image)
    _, separator, digest = inspection.stdout.strip().partition("@")
    return digest if inspection.returncode == 0 and separator else None


def _docker(*args: str) -> "subprocess.CompletedProcess[str]":
    command = ["docker", *args]
    try:
        return subprocess.run(command, check=False, capture_output=True, text=True)
    except OSError as failure:
        # No `docker` on the PATH at all. The caller reads a failed run, as it would
        # from a daemon that did not answer, so `available()` says no instead of
        # raising past the refusal that names the ways forward.
        return subprocess.CompletedProcess(command, returncode=127, stdout="", stderr=str(failure))


class DockerError(ValueError):
    """The daemon's own message, for a launch that cannot proceed without the image."""
