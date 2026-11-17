# The audit names the container a launch leaves unnamed, keeps the name a launch gives, and
# refuses a launch whose name it cannot read. These pin that no launch of either suite is refused,
# without Docker: the modules that build them are fingerprinted and do not change for this.
from pathlib import Path

import pytest

import tests.unit.cve.backends.support.test_audited_launch_names_given as given
from mcp_auditor.domain.confinement import Undecidable, declared_container_name

_NAMED = given.named_server_args()
_UNNAMED = given.unnamed_launch_builders()


@pytest.mark.parametrize("server_args", _NAMED.values(), ids=list(_NAMED))
def test_a_server_beside_its_backend_reads_to_the_name_it_was_given(
    server_args: given.ServerArgs,
):
    assert declared_container_name(given.run_args_of(server_args)) == given.SERVER


@pytest.mark.parametrize("builder", _UNNAMED.values(), ids=list(_UNNAMED))
def test_every_other_audited_launch_reads_to_its_own_name_or_to_none(
    builder: given.ArgvBuilder, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    with given.built(builder, tmp_path, monkeypatch) as args:
        assert declared_container_name(args) is not Undecidable.NAME
