import logging
import re
import tempfile
from pathlib import Path

import pytest

import tests.unit.support.fictional_planting as planting
from evals.cve.planting import DockerPlanting, PlantingFailed, planted

# --- account materialisation and file mode ----------------------------------------------


def test_a_planted_file_is_written_mode_0644_with_the_nonce():
    spec = planting.spec_of([planting.file_place(path="/etc/x")])
    docker = planting.FakePlantingDocker()

    with planted(spec, "image:tag", docker):
        host_file = _only_value(docker.host_files)
        assert host_file.mode == 0o644
        assert host_file.content == spec.nonces["file-1"]


def test_an_account_emits_a_passwd_entry_under_the_fixed_uid_and_replaces_the_user_args():
    spec = planting.spec_of([planting.account_place()])
    docker = planting.FakePlantingDocker()

    with planted(spec, "image:tag", docker) as args:
        name = spec.nonces["account-1"]
        assert args.user == ("--user", "60123:60123", "-e", "HOME=/tmp")
        assert "-v" in args.mounts
        passwd = _passwd_content(docker)
        assert "root:x:0:0" in passwd  # the image's own entries are kept
        assert f"{name}:x:60123:60123::/tmp:" in passwd
        group = next(
            f.content for f in docker.host_files.values() if f"{name}:x:60123:\n" in f.content
        )
        assert "root:x:0:\n" in group  # the image's own group entries are kept


# --- failures and teardown --------------------------------------------------------------


def test_a_sentinel_that_does_not_serve_raises_and_leaves_nothing_alive():
    spec = planting.spec_of(
        [planting.endpoint_place(host="198.51.100.5")], host=planting.unprivileged_host()
    )
    docker = planting.FakePlantingDocker(dead_sentinels=frozenset({"198.51.100.5"}))

    with (
        pytest.raises(PlantingFailed, match=re.escape("198.51.100.5")),
        planted(spec, "image:tag", docker),
    ):
        pass

    planting.nothing_left_alive(docker)


def test_a_setup_failure_after_the_holder_undoes_everything_and_raises_planting_failed():
    spec = planting.spec_of(
        [
            planting.endpoint_place("endpoint-1", host="198.51.100.5"),
            planting.endpoint_place("endpoint-2", host="203.0.113.7"),
        ],
        host=planting.unprivileged_host(has_network=True),
    )
    docker = planting.FakePlantingDocker(fail={"start_sentinel": 1})  # the second sentinel fails

    with pytest.raises(PlantingFailed), planted(spec, "image:tag", docker):
        pass

    planting.nothing_left_alive(docker)


def test_a_host_file_that_cannot_be_written_raises_planting_failed():
    spec = planting.spec_of([planting.file_place(path="/etc/x")])
    docker = planting.FakePlantingDocker(fail={"write_host_file": 0})

    with pytest.raises(PlantingFailed), planted(spec, "image:tag", docker):
        pass


def test_teardown_leaves_nothing_alive_under_the_network_removal_refusal():
    spec = planting.spec_of(
        [planting.endpoint_place(host="198.51.100.5"), planting.file_place(path="/etc/x")],
        host=planting.unprivileged_host(has_network=True),
    )
    docker = planting.FakePlantingDocker()

    with planted(spec, "image:tag", docker):
        assert docker.networks and docker.holders and docker.sentinels and docker.host_files

    planting.nothing_left_alive(docker)


def test_a_teardown_failure_is_logged_and_the_rest_of_the_teardown_still_runs(
    caplog: pytest.LogCaptureFixture,
):
    spec = planting.spec_of(
        [planting.endpoint_place(host="198.51.100.5")], host=planting.unprivileged_host()
    )
    docker = planting.FakePlantingDocker(fail_teardown=frozenset({"remove_sentinel"}))

    with caplog.at_level(logging.DEBUG), planted(spec, "image:tag", docker):
        pass  # no exception escapes the block

    assert docker.holders == {}  # the sentinel failure did not abort the holder's removal
    assert "planting teardown failed" in caplog.text


def test_a_non_infra_setup_failure_undoes_everything_and_re_raises_as_itself():
    spec = planting.spec_of(
        [planting.endpoint_place(host="198.51.100.5"), planting.file_place(path="/etc/x")],
        host=planting.unprivileged_host(has_network=True),
    )
    docker = planting.FakePlantingDocker(
        fail={"start_sentinel": 0}, fail_errors={"start_sentinel": RuntimeError("sentinel boom")}
    )

    with pytest.raises(RuntimeError, match="sentinel boom"), planted(spec, "image:tag", docker):
        pass

    planting.nothing_left_alive(docker)


def test_a_non_utf8_passwd_read_raises_planting_failed():
    spec = planting.spec_of([planting.account_place()])
    decode_error = UnicodeDecodeError("utf-8", b"\xff", 0, 1, "invalid start byte")
    docker = planting.FakePlantingDocker(
        fail={"image_accounts": 0}, fail_errors={"image_accounts": decode_error}
    )

    with pytest.raises(PlantingFailed), planted(spec, "image:tag", docker):
        pass


def test_write_host_file_removes_the_temp_file_when_the_content_cannot_be_encoded(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    monkeypatch.setattr(tempfile, "tempdir", str(tmp_path))

    with pytest.raises(UnicodeEncodeError):
        DockerPlanting().write_host_file("\ud800", 0o644)

    assert list(tmp_path.iterdir()) == []


def test_the_docker_adapter_refuses_to_remove_a_directory_that_is_no_layout_outer(
    tmp_path: Path,
):
    with pytest.raises(PlantingFailed):
        DockerPlanting().remove_layout(str(tmp_path))


def _only_value(mapping: dict[str, planting.HostFile]) -> planting.HostFile:
    assert len(mapping) == 1
    return next(iter(mapping.values()))


def _passwd_content(docker: planting.FakePlantingDocker) -> str:
    return next(f.content for f in docker.host_files.values() if "root:x:0:0" in f.content)
