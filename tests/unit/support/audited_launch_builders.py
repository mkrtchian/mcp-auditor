"""Every builder of an audited launch, run on fakes so no builder makes a Docker call.

The table is keyed by the builder a target names (`Target.builder`), with the backend modules and
the images a target built by it must declare. Beside it, the launches no target names: the kit
builders a calibration kit runs, and the nuisance single-container launches. A layout builder on
an empty spec plants nothing, though it still calls `build_layout`, which shells out to host `git`.
"""

import dataclasses
from collections.abc import Callable, Generator
from contextlib import AbstractContextManager, contextmanager
from pathlib import Path
from typing import Any, Protocol

import pytest

import tests.unit.cve.backends.support.backend_launch_specs as specs
import tests.unit.cve.backends.support.doris_launch as doris_launch
import tests.unit.cve.backends.support.test_ckan_holdout_builder_given as ckan_given
import tests.unit.cve.backends.support.test_kubernetes_backend_given as kubernetes_given
import tests.unit.cve.backends.support.test_searxng_backend_given as searxng_given
import tests.unit.cve.support.test_cve_planting_stand_ins_given as stand_ins
import tests.unit.support.fake_sshd as fake_sshd
from evals.cve.backends import (
    backend_beside_launch,
    ckan,
    ckan_holdout,
    doris,
    kubernetes,
    kubernetes_detection,
    mcp_ssh_holdout,
    n8n_instance,
    searxng,
)
from evals.cve.backends.ckan_holdout import ckan_ssrf_env
from evals.cve.backends.kubernetes import CONTROL_PLANE_SERVICE
from evals.cve.backends.kubernetes_detection import kubernetes_injection_env
from evals.cve.backends.mcp_ssh_holdout import mcp_ssh_injection_env
from evals.cve.backends.searxng import SEARXNG_SERVICE, searxng_env
from evals.cve.detection.holdout_environments import (
    arcadedb_mcp_env,
    command_injection_checkout_env,
    doris_db_env,
    filesystem_scope_env,
    houtini_lm_env,
    mysql_db_env,
    ssrf_redirect_env,
)
from evals.cve.environments import (
    command_injection_env,
    filesystem_env,
    git_init_traversal_env,
    ssrf_env,
)
from evals.cve.kit import launch as kit_launch
from evals.cve.nuisance.confinement import single_container_launch_args, single_container_run_args
from evals.cve.planting import RANDOM_NONCES, PlantingSpec, planting_spec
from evals.cve.planting_base import LayoutMount, PlantingHost, PublicNames, SymbolicUser
from tests.fakes.planting_docker import FakePlantingDocker

_IMAGE = "img"


type Builder = Callable[..., AbstractContextManager[Any]]


class SpecBuilder(Protocol):
    def __call__(
        self, image: str, spec: PlantingSpec, *, docker: FakePlantingDocker
    ) -> AbstractContextManager[Any]: ...


@dataclasses.dataclass(frozen=True)
class BuiltLaunch:
    args: list[str]
    host: PlantingHost  # the planting host of the spec the launch was built from


type LaunchOnFakes = Callable[[Path, pytest.MonkeyPatch], AbstractContextManager[BuiltLaunch]]


@dataclasses.dataclass(frozen=True)
class AuditedLaunchBuilder:
    launched: LaunchOnFakes
    backend_sources: frozenset[Path] = frozenset()  # what a target built by it must fingerprint
    images: frozenset[str] = frozenset()  # the compose services a target built by it must build
    takes_an_empty_spec: bool = False  # the key itself runs on `an_empty_spec`


def _on_an_empty_spec(
    builder: SpecBuilder, backend_sources: frozenset[Path] = frozenset()
) -> AuditedLaunchBuilder:
    @contextmanager
    def launched(_tmp_path: Path, _monkeypatch: pytest.MonkeyPatch) -> Generator[BuiltLaunch]:
        spec = an_empty_spec()
        with builder(_IMAGE, spec, docker=FakePlantingDocker()) as launch:
            yield BuiltLaunch(launch.args, spec.host)

    return AuditedLaunchBuilder(launched, backend_sources, takes_an_empty_spec=True)


def an_empty_spec(mount: LayoutMount = LayoutMount.READ_ONLY) -> PlantingSpec:
    host = PlantingHost(SymbolicUser.UNPRIVILEGED, "/", has_network=False, layout_mount=mount)
    return planting_spec((), host, RANDOM_NONCES)


@contextmanager
def _doris(_tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Generator[BuiltLaunch]:
    doris_launch.doris_helpers_faked(monkeypatch, doris_launch.OverlapRecorder())
    spec = doris_launch.a_minimal_doris_spec()
    with doris_db_env(_IMAGE, spec, docker=FakePlantingDocker()) as launch:
        yield BuiltLaunch(launch.args, spec.host)


@contextmanager
def _ckan(_tmp_path: Path, _monkeypatch: pytest.MonkeyPatch) -> Generator[BuiltLaunch]:
    spec = ckan_given.the_targets_spec()
    stack = ckan_given.FakeCkanDocker().docker()
    with ckan_ssrf_env(_IMAGE, spec, docker=FakePlantingDocker(), ckan=stack) as launch:
        yield BuiltLaunch(launch.args, spec.host)


@contextmanager
def _kubernetes(tmp_path: Path, _monkeypatch: pytest.MonkeyPatch) -> Generator[BuiltLaunch]:
    spec = specs.a_spec_with_a_holder()
    control_plane = kubernetes_given.a_control_plane(tmp_path).docker()
    with kubernetes_injection_env(
        _IMAGE, spec, docker=FakePlantingDocker(), control_plane=control_plane
    ) as launch:
        yield BuiltLaunch(launch.args, spec.host)


@contextmanager
def _mcp_ssh(tmp_path: Path, _monkeypatch: pytest.MonkeyPatch) -> Generator[BuiltLaunch]:
    spec = specs.a_spec_with_a_holder()
    sshd = fake_sshd.an_sshd(tmp_path).docker()
    with mcp_ssh_injection_env(_IMAGE, spec, docker=FakePlantingDocker(), sshd=sshd) as launch:
        yield BuiltLaunch(launch.args, spec.host)


@contextmanager
def _searxng(_tmp_path: Path, _monkeypatch: pytest.MonkeyPatch) -> Generator[BuiltLaunch]:
    spec = searxng_given.the_targets_spec()
    planting = FakePlantingDocker()
    stand = searxng_given.FakeSearxng(planting).docker()
    with searxng_env(_IMAGE, spec, docker=planting, searxng=stand) as launch:
        yield BuiltLaunch(launch.args, spec.host)


def _sources(*modules: Any) -> frozenset[Path]:
    return frozenset(Path(module.__file__) for module in modules)


AUDITED_LAUNCH_BUILDERS: dict[Builder, AuditedLaunchBuilder] = {
    filesystem_env: _on_an_empty_spec(filesystem_env),
    git_init_traversal_env: _on_an_empty_spec(git_init_traversal_env),
    command_injection_env: _on_an_empty_spec(command_injection_env),
    ssrf_env: _on_an_empty_spec(ssrf_env),
    arcadedb_mcp_env: _on_an_empty_spec(arcadedb_mcp_env),
    filesystem_scope_env: _on_an_empty_spec(filesystem_scope_env),
    ssrf_redirect_env: _on_an_empty_spec(ssrf_redirect_env, _sources(n8n_instance)),
    mysql_db_env: _on_an_empty_spec(mysql_db_env),
    command_injection_checkout_env: _on_an_empty_spec(command_injection_checkout_env),
    houtini_lm_env: _on_an_empty_spec(houtini_lm_env),
    doris_db_env: AuditedLaunchBuilder(_doris, backend_sources=_sources(doris)),
    kubernetes_injection_env: AuditedLaunchBuilder(
        _kubernetes,
        backend_sources=_sources(kubernetes, kubernetes_detection, backend_beside_launch),
        images=frozenset({CONTROL_PLANE_SERVICE}),
    ),
    mcp_ssh_injection_env: AuditedLaunchBuilder(
        _mcp_ssh, backend_sources=_sources(mcp_ssh_holdout, backend_beside_launch)
    ),
    searxng_env: AuditedLaunchBuilder(
        _searxng, backend_sources=_sources(searxng), images=frozenset({SEARXNG_SERVICE})
    ),
    ckan_ssrf_env: AuditedLaunchBuilder(_ckan, backend_sources=_sources(ckan_holdout, ckan, doris)),
}


# The launches a calibration kit runs, copies of the builders above that no target names.
KIT_BUILDERS: dict[str, SpecBuilder] = {
    "kit filesystem": kit_launch.filesystem_env,
    "kit git_init_traversal": kit_launch.git_init_traversal_env,
    "kit command_injection": kit_launch.command_injection_env,
    "kit ssrf": kit_launch.ssrf_env,
    "kit arcadedb": kit_launch.arcadedb_env,
}


_NUISANCE_HOST = PlantingHost(SymbolicUser.UNPRIVILEGED, "/", has_network=True)
_NUISANCE_LAUNCH = ("serve",)


@contextmanager
def _single_container(_tmp_path: Path, _monkeypatch: pytest.MonkeyPatch) -> Generator[BuiltLaunch]:
    yield BuiltLaunch(
        single_container_run_args(_IMAGE, _NUISANCE_HOST, _NUISANCE_LAUNCH), _NUISANCE_HOST
    )


@contextmanager
def _single_container_with_a_public_name(
    tmp_path: Path, _monkeypatch: pytest.MonkeyPatch
) -> Generator[BuiltLaunch]:
    directory = stand_ins.a_stand_ins_directory(tmp_path)
    names = PublicNames(stand_ins=(stand_ins.HOST,))
    host = dataclasses.replace(_NUISANCE_HOST, public_names=names)
    with single_container_launch_args(
        _IMAGE, host, _NUISANCE_LAUNCH, docker=FakePlantingDocker(), stand_ins_directory=directory
    ) as args:
        yield BuiltLaunch(args, host)


# The nuisance launches of a server with no backend, which no target names.
NUISANCE_LAUNCHES: dict[str, LaunchOnFakes] = {
    "single_container_run_args": _single_container,
    "single_container_launch_args": _single_container_with_a_public_name,
}
