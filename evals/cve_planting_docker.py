"""The production `PlantingDocker` port that drives Docker and the host filesystem for planting.

Setup calls run with `check=True` so a failure raises before a launch is yielded. Teardown
calls are best-effort and never raise. Every network and container carries the
`mcp-auditor-cve` label, so an orphan left by a crashed run is swept by label and never
blocks a later launch. Every network is closed (`closed_network`): internal, with an isolated
gateway, so a launch reaches neither the host nor the Internet.

The `/srv` layout is handed over to the unprivileged account and removed by two short-lived
containers of `LAYOUT_HELPER_IMAGE`, since the host user can neither chown it nor delete what
the account owns. Docker pulls the helper on first use, so the first launch needs network once.
"""

import logging
import os
import secrets
import subprocess
import tempfile
import time
from collections.abc import Sequence

from evals.closed_network import create_closed_network
from evals.cve_planting_base import (
    LABEL,
    LAYOUT_ROOT,
    UNPRIVILEGED_GID,
    UNPRIVILEGED_UID,
    ImageAccounts,
    PlantingDocker,
    PlantingFailed,
    check_layout_outer,
    confinement_args,
    no_network_args,
    quiet,
)
from evals.cve_planting_base import (
    SENTINEL_IMAGE as SENTINEL_IMAGE,
)

logger = logging.getLogger(__name__)

# The sentinel's base, pinned by digest: it needs no compose build and the kit carries it.
LAYOUT_HELPER_IMAGE = (
    "busybox:latest@sha256:fd8d9aa63ba2f0982b5304e1ee8d3b90a210bc1ffb5314d980eb6962f1a9715d"
)
# Generous enough for a healthy sentinel under concurrency, and to wait out httpd start-up:
# paid in full only on a real failure, since a serving sentinel answers on an early retry.
_SENTINEL_PROBE_BUDGET = 15.0
_SENTINEL_PROBE_INTERVAL = 0.2
# Bounds the busybox `wget` and `nc` inside the probe container, `wget` otherwise waiting 900 s.
_SENTINEL_FETCH_TIMEOUT = 5.0
# Above the fetch bound by a container start-up margin: a shared value would let the subprocess
# timeout fire before `wget`'s own whenever a probe container starts slowly.
_PROBE_RUN_TIMEOUT = 10.0
_MISS_PREFIX = "miss "


def _best_effort(*command: str) -> None:
    try:
        result = subprocess.run(list(command), check=False, capture_output=True, text=True)
    except OSError as error:
        logger.warning("cleanup command failed: %s (%s)", " ".join(command), error)
        return
    if result.returncode != 0:
        logger.warning("cleanup command failed: %s (%s)", " ".join(command), result.stderr.strip())


class DockerPlanting(PlantingDocker):
    """Drives Docker and the host filesystem, labelling every network and container it makes."""

    def image_accounts(self, image_tag: str) -> ImageAccounts:
        return ImageAccounts(
            self._read(image_tag, "/etc/passwd"), self._read(image_tag, "/etc/group")
        )

    def write_host_file(self, content: str, mode: int) -> str:
        descriptor, path = tempfile.mkstemp(prefix=f"{LABEL}-")
        try:
            with os.fdopen(descriptor, "w") as handle:
                handle.write(content)
            os.chmod(path, mode)
        except BaseException:
            os.unlink(path)
            raise
        return path

    def remove_host_file(self, path: str) -> None:
        quiet(os.unlink, path)

    def create_network(self) -> str:
        name = f"{LABEL}-{secrets.token_hex(6)}"
        create_closed_network(name)
        return name

    def remove_network(self, name: str) -> None:
        _best_effort("docker", "network", "rm", name)

    def start_holder(self, run_args: Sequence[str]) -> str:
        return self._run_detached(run_args)

    def remove_holder(self, name: str) -> None:
        _best_effort("docker", "rm", "-f", name)

    def start_sentinel(self, run_args: Sequence[str]) -> str:
        return self._run_detached(run_args)

    def remove_sentinel(self, name: str) -> None:
        _best_effort("docker", "rm", "-f", name)

    def start_stand_in(self, run_args: Sequence[str]) -> str:
        return self._run_detached(run_args)

    def remove_stand_in(self, name: str, host: str) -> None:
        # Read before the removal: `--rm` drops the logs with the container.
        for line in _stand_in_stderr(name).splitlines():
            if line.startswith(_MISS_PREFIX):
                logger.warning("stand-in for %s answered with its default for: %s", host, line)
        _best_effort("docker", "rm", "-f", name)

    def probe_endpoint(self, target_args: Sequence[str], url: str) -> str | None:
        deadline = time.monotonic() + _SENTINEL_PROBE_BUDGET
        while True:
            body = _probe_read(target_args, url)
            if body is not None or time.monotonic() >= deadline:
                return body
            time.sleep(_SENTINEL_PROBE_INTERVAL)

    def probe_listener(self, target_args: Sequence[str], host: str, port: int) -> bool:
        deadline = time.monotonic() + _SENTINEL_PROBE_BUDGET
        while True:
            if _probe_connect(target_args, host, port):
                return True
            if time.monotonic() >= deadline:
                return False
            time.sleep(_SENTINEL_PROBE_INTERVAL)

    def hand_over_layout(self, root: str) -> None:
        # `-h`: a leak link points at a container path absent from the helper, never followed.
        owner = f"{UNPRIVILEGED_UID}:{UNPRIVILEGED_GID}"
        command = [*_layout_helper("CHOWN"), "-v", f"{root}:/srv", LAYOUT_HELPER_IMAGE]
        command += ["chown", "-hR", owner, "/srv"]
        try:
            result = subprocess.run(command, check=False, capture_output=True, text=True)
        except OSError as error:
            raise PlantingFailed(f"cannot hand the layout over: {error}") from error
        if result.returncode != 0:
            raise PlantingFailed(f"cannot hand the layout over: {result.stderr.strip()}")

    def remove_layout(self, outer: str) -> None:
        # FOWNER beside DAC_OVERRIDE: a sticky directory a read-write server made keeps its
        # entries from any other uid that does not own them.
        check_layout_outer(outer)
        _best_effort(
            *_layout_helper("DAC_OVERRIDE", "FOWNER"),
            "-v",
            f"{outer}:/x",
            LAYOUT_HELPER_IMAGE,
            "rm",
            "-rf",
            f"/x/{LAYOUT_ROOT}",
        )

    def run_address_setup(self, run_args: Sequence[str]) -> None:
        subprocess.run(
            ["docker", "run", "--rm", "--label", LABEL, *run_args], check=True, capture_output=True
        )

    def _read(self, image_tag: str, path: str) -> str:
        result = subprocess.run(
            [
                "docker",
                "run",
                "--rm",
                "--label",
                LABEL,
                *confinement_args(),
                "--entrypoint",
                "cat",
                image_tag,
                path,
            ],
            check=True,
            capture_output=True,
            text=True,
        )
        return result.stdout

    def _run_detached(self, run_args: Sequence[str]) -> str:
        name = f"{LABEL}-{secrets.token_hex(6)}"
        subprocess.run(
            ["docker", "run", "-d", "--rm", "--label", LABEL, "--name", name, *run_args],
            check=True,
            capture_output=True,
        )
        return name


def _layout_helper(*capabilities: str) -> list[str]:
    added = [option for capability in capabilities for option in ("--cap-add", capability)]
    return [
        "docker", "run", "--rm", "--label", LABEL, "--user", "0:0", "--cap-drop", "ALL", *added,
        "--security-opt", "no-new-privileges", *no_network_args(),
    ]  # fmt: skip


DOCKER_PLANTING = DockerPlanting()


def _probe_read(target_args: Sequence[str], url: str) -> str | None:
    # The entrypoint is absolute because an env place named PATH travels in `target_args`, and
    # `-Y off` because a planted `http_proxy` travels too: busybox `wget` would honour it, the
    # target's client does not.
    try:
        result = subprocess.run(
            [
                "docker",
                "run",
                "--rm",
                "--label",
                LABEL,
                *target_args,
                "--entrypoint",
                "/bin/wget",
                SENTINEL_IMAGE,
                "-Y",
                "off",
                "-qO-",
                "-T",
                f"{_SENTINEL_FETCH_TIMEOUT:g}",
                url,
            ],
            check=False,
            capture_output=True,
            text=True,
            timeout=_PROBE_RUN_TIMEOUT,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    return result.stdout if result.returncode == 0 else None


def _probe_connect(target_args: Sequence[str], host: str, port: int) -> bool:
    command = ["docker", "run", "--rm", "--label", LABEL, *target_args, "--entrypoint", "/bin/nc"]
    command += [SENTINEL_IMAGE, "-z", "-w", f"{_SENTINEL_FETCH_TIMEOUT:g}", host, str(port)]
    try:
        result = subprocess.run(
            command, check=False, capture_output=True, timeout=_PROBE_RUN_TIMEOUT
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    return result.returncode == 0


def _stand_in_stderr(name: str) -> str:
    try:
        result = subprocess.run(
            ["docker", "logs", name], check=False, capture_output=True, text=True, errors="replace"
        )
    except OSError as error:
        logger.warning("cannot read the logs of stand-in %s: %s", name, error)
        return ""
    return result.stderr
