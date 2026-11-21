import dataclasses
from collections.abc import Callable, Generator, Sequence
from contextlib import contextmanager
from pathlib import Path

import pytest

import tests.unit.cve.backends.support.backend_launch_specs as specs
import tests.unit.cve.backends.support.doris_launch as doris
import tests.unit.cve.backends.support.test_ckan_holdout_builder_given as ckan
import tests.unit.cve.backends.support.test_kubernetes_backend_given as kubernetes
import tests.unit.cve.backends.support.test_mcp_ssh_holdout_builder_given as mcp_ssh
import tests.unit.cve.backends.support.test_searxng_backend_given as searxng
import tests.unit.cve.support.test_cve_planting_stand_ins_given as stand_ins
from evals.cve.backends import gitlab, node_sandbox_engine
from evals.cve.backends import kubernetes as kubernetes_backend
from evals.cve.backends.facebook_ads import FACEBOOK_ADS_RESPONDER
from evals.cve.backends.gitlab import StoodGitLab
from evals.cve.backends.kubernetes import StoodControlPlane
from evals.cve.backends.kubernetes_detection import kubernetes_injection_env
from evals.cve.backends.lifecycle import BackendLifecycle
from evals.cve.backends.mcp_ssh_holdout import mcp_ssh_injection_env
from evals.cve.detection import holdout_environments
from evals.cve.nuisance.backend_registry import BACKENDS
from evals.cve.nuisance.confinement import single_container_launch_args, single_container_run_args
from evals.cve.planting_base import PlantingHost, PublicNames, SymbolicUser
from tests.fakes.planting_docker import FakePlantingDocker

SERVER = "server-name"
_IMAGE = "img"
_HOST = PlantingHost(SymbolicUser.UNPRIVILEGED, "/", has_network=True)
_LAUNCH = ("serve",)

type ServerArgs = Callable[[str, str, PlantingHost, Sequence[str]], list[str]]
# Each builder yields the server's run argv, given the test's temp directory and monkeypatch.
type ArgvBuilder = Callable[[Path, pytest.MonkeyPatch], Generator[list[str]]]


def named_server_args() -> dict[str, ServerArgs]:
    """Every function that returns, for a server it names, the run argv of a nuisance server
    beside its backend: each shared backend's `server_args`, the responders' method, and each
    per-launch backend's `server_run_args` with its backend stood."""
    shared = {
        key: entry.lifecycle.server_args
        for key, entry in BACKENDS.items()
        if isinstance(entry.lifecycle, BackendLifecycle)
    }
    return {
        **shared,
        "Responder.server_args": FACEBOOK_ADS_RESPONDER.server_args,
        "kubernetes server_run_args": _with_a_control_plane,
        "gitlab server_run_args": _with_a_gitlab,
        "node_sandbox_engine server_run_args": _with_an_engine,
    }


def run_args_of(server_args: ServerArgs) -> list[str]:
    return server_args(SERVER, _IMAGE, _HOST, _LAUNCH)


def _with_a_control_plane(
    name: str, image: str, host: PlantingHost, launch: Sequence[str]
) -> list[str]:
    stood = StoodControlPlane("kube-net", Path("/tmp/admin.conf"))
    return kubernetes_backend.server_run_args(name, image, host, launch, stood)


def _with_a_gitlab(name: str, image: str, host: PlantingHost, launch: Sequence[str]) -> list[str]:
    return gitlab.server_run_args(name, image, host, launch, StoodGitLab("gitlab-net", "token"))


def _with_an_engine(name: str, image: str, host: PlantingHost, launch: Sequence[str]) -> list[str]:
    return node_sandbox_engine.server_run_args(name, image, host, launch, Path("/tmp/engine.sock"))


def unnamed_launch_builders() -> dict[str, ArgvBuilder]:
    """Every other function that returns the run argv of an audited server: the detection
    builders with a backend, run on fakes, and the nuisance single-container launch."""
    return {
        "ckan_holdout": _ckan,
        "doris_db_env": _doris,
        "kubernetes_injection_env": _kubernetes,
        "mcp_ssh_injection_env": _mcp_ssh,
        "searxng_env": _searxng,
        "single_container_run_args": _single_container,
        "single_container_launch_args": _single_container_with_a_public_name,
    }


@contextmanager
def built(
    builder: ArgvBuilder, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> Generator[list[str]]:
    yield from builder(tmp_path, monkeypatch)


def _ckan(_tmp_path: Path, _monkeypatch: pytest.MonkeyPatch) -> Generator[list[str]]:
    with ckan.a_launch() as launch:
        yield launch.args


def _doris(_tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Generator[list[str]]:
    doris.doris_helpers_faked(monkeypatch, doris.OverlapRecorder())
    spec = doris.a_minimal_doris_spec()
    with holdout_environments.doris_db_env(_IMAGE, spec, docker=FakePlantingDocker()) as launch:
        yield launch.args


def _kubernetes(tmp_path: Path, _monkeypatch: pytest.MonkeyPatch) -> Generator[list[str]]:
    control_plane = kubernetes.a_control_plane(tmp_path).docker()
    spec = specs.a_spec_with_a_holder()
    planting = FakePlantingDocker()
    with kubernetes_injection_env(
        _IMAGE, spec, docker=planting, control_plane=control_plane
    ) as launch:
        yield launch.args


def _mcp_ssh(tmp_path: Path, _monkeypatch: pytest.MonkeyPatch) -> Generator[list[str]]:
    sshd = mcp_ssh.an_sshd(tmp_path).docker()
    spec = specs.a_spec_with_a_holder()
    with mcp_ssh_injection_env(_IMAGE, spec, docker=FakePlantingDocker(), sshd=sshd) as launch:
        yield launch.args


def _searxng(_tmp_path: Path, _monkeypatch: pytest.MonkeyPatch) -> Generator[list[str]]:
    planting = FakePlantingDocker()
    with searxng.a_launch(planting, searxng.a_searxng(planting)) as launch:
        yield launch.args


def _single_container(_tmp_path: Path, _monkeypatch: pytest.MonkeyPatch) -> Generator[list[str]]:
    yield single_container_run_args(_IMAGE, _HOST, _LAUNCH)


def _single_container_with_a_public_name(
    tmp_path: Path, _monkeypatch: pytest.MonkeyPatch
) -> Generator[list[str]]:
    directory = stand_ins.a_stand_ins_directory(tmp_path)
    host = dataclasses.replace(_HOST, public_names=PublicNames(stand_ins=(stand_ins.HOST,)))
    with single_container_launch_args(
        _IMAGE, host, _LAUNCH, docker=FakePlantingDocker(), stand_ins_directory=directory
    ) as args:
        yield args
