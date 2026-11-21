import stat
from pathlib import Path

import pytest

import tests.unit.cve.backends.support.backend_launch_specs as specs
import tests.unit.cve.backends.support.test_mcp_ssh_holdout_builder_given as given
from evals.cve.backends.mcp_ssh_holdout import mcp_ssh_injection_env
from evals.cve.backends.mcp_ssh_sshd import (
    CALLER,
    KNOWN_HOSTS,
    ROOT,
    RUN_KNOWN_HOSTS,
    SSHD_ALIAS,
    SSHD_IMAGE,
    StoodSshd,
    install_known_hosts,
    known_hosts_text,
    sshd_args,
    sshd_server_args,
)
from evals.cve.dossier_closure import import_closure
from evals.cve.nuisance.fix_checks import mcp_ssh_fix_check as fix_check
from evals.cve.planting_base import PlantingHost, SymbolicUser
from tests.fakes.planting_docker import FakePlantingDocker
from tests.unit.support.docker_argv import carries, mount_of, value_after, values_after
from tests.unit.support.recorded_subprocess import recorded_commands


def test_the_sshd_module_carries_no_auditor_or_environment_module_into_a_dossier():
    closure = import_closure(["evals.cve.backends.mcp_ssh_sshd"])

    assert not [module for module in closure if module.startswith("mcp_auditor")]
    assert "evals.cve.environments" not in closure


def test_the_sshd_runs_in_its_own_namespace_under_the_readme_hostname():
    args = sshd_args("sshd", "net")

    assert values_after(args, "--network") == ["net"]
    assert not [arg for arg in args if arg.startswith("container:")]
    assert value_after(args, "--network-alias") == SSHD_ALIAS
    assert args[-1] == SSHD_IMAGE


def test_known_hosts_names_the_sshd_by_the_hostname_the_config_entry_names():
    scanned = "# 127.0.0.1:22 SSH-2.0-OpenSSH_10.6\n" + given.SCANNED

    assert known_hosts_text(scanned) == (
        f"{SSHD_ALIAS} ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQ\n"
        f"{SSHD_ALIAS} ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOk\n"
    )


def test_known_hosts_is_installed_mode_0644_and_handed_to_its_owner_with_chown_alone(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    commands = recorded_commands(monkeypatch)
    path = tmp_path / "known_hosts"

    install_known_hosts(path, "prod.example.com ssh-ed25519 AAAA\n", ROOT)

    assert path.read_text() == "prod.example.com ssh-ed25519 AAAA\n"
    assert stat.S_IMODE(path.stat().st_mode) == 0o644
    [chown] = commands
    assert chown[-3:-1] == ["chown", ROOT]
    assert carries(chown, ["--cap-drop", "ALL", "--cap-add", "CHOWN"])
    assert value_after(chown, "--network") == "none"


def test_the_holdout_launch_mounts_a_root_owned_known_hosts_read_only(tmp_path: Path):
    sshd = given.an_sshd(tmp_path)

    with mcp_ssh_injection_env(
        "img", specs.a_spec_with_a_holder(), docker=FakePlantingDocker(), sshd=sshd.docker()
    ) as launch:
        assert mount_of(launch.args, KNOWN_HOSTS) == f"{sshd.known_hosts}:{KNOWN_HOSTS}:ro"
        assert sshd.owners == [ROOT]


def test_the_holdout_launch_refuses_a_host_with_no_network(tmp_path: Path):
    sshd = given.an_sshd(tmp_path)

    with (
        pytest.raises(ValueError, match="has_network"),
        mcp_ssh_injection_env(
            "img", specs.a_spec_with_no_network(), docker=FakePlantingDocker(), sshd=sshd.docker()
        ),
    ):
        pass

    assert sshd.owners == []


def test_the_nuisance_run_launch_mounts_the_callers_known_hosts_read_only():
    host = PlantingHost(SymbolicUser.UNPRIVILEGED, "/", has_network=False)

    args = sshd_server_args("server", "img", host, [])

    assert mount_of(args, KNOWN_HOSTS) == f"{RUN_KNOWN_HOSTS}:{KNOWN_HOSTS}:ro"


def test_the_fix_check_stands_its_sshd_with_a_known_hosts_the_caller_owns(tmp_path: Path):
    sshd = given.an_sshd(tmp_path)
    spec = fix_check.target(
        flaw="CVE-2025-9654",
        aim=fix_check.re.compile(r'";'),
        injection=fix_check.shell_injection,
        vulnerable_service="mcp-ssh-flaw-1.0.3",
        patched_service="mcp-ssh-flaw-1.0.4",
        server_patched_service="mcp-ssh",
    ).planting_spec()

    with fix_check.ssh_env("img", spec, stand=sshd.stand) as launch:
        assert sshd.owners == [CALLER]
        assert mount_of(launch.args, KNOWN_HOSTS) == f"{sshd.known_hosts}:{KNOWN_HOSTS}:ro"
        assert value_after(launch.args, "--network") == "sshd-net-1"


def test_the_fix_check_server_mounts_the_known_hosts_beside_the_witness():
    args = fix_check.server_args("img", StoodSshd("net", Path("/k/known_hosts")), "/tmp/w")

    assert mount_of(args, KNOWN_HOSTS) == f"/k/known_hosts:{KNOWN_HOSTS}:ro"
    assert mount_of(args, fix_check.WITNESS_PATH) == f"/tmp/w:{fix_check.WITNESS_PATH}:ro"
