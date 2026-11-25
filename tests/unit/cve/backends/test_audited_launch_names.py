# The audit names the container a launch leaves unnamed, keeps the name a launch gives, and
# refuses a launch whose name it cannot read. These pin that no launch of either suite is refused,
# without Docker: the modules that build them are fingerprinted and do not change for this.
from pathlib import Path

import pytest

import tests.unit.cve.backends.support.test_audited_launch_names_given as given
from evals.cve.environments import Launch
from evals.cve.launch_audit import named
from mcp_auditor.domain.container_name import declared_container_name
from tests.unit.support.audited_launch_builders import (
    AUDITED_LAUNCH_BUILDERS,
    NUISANCE_LAUNCHES,
    LaunchOnFakes,
)

_NAMED = given.named_run_args()
_AUDITED = {
    **{builder.__name__: entry.launched for builder, entry in AUDITED_LAUNCH_BUILDERS.items()},
    **NUISANCE_LAUNCHES,
}


@pytest.mark.parametrize("run_args", _NAMED.values(), ids=list(_NAMED))
def test_a_server_beside_its_backend_reads_to_the_name_it_was_given(run_args: list[str]):
    assert declared_container_name(run_args) == given.SERVER


@pytest.mark.parametrize("launched", _AUDITED.values(), ids=list(_AUDITED))
def test_every_other_audited_launch_reads_to_a_name_once_the_audit_names_it(
    launched: LaunchOnFakes, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    with launched(tmp_path, monkeypatch) as built:
        audited = named(Launch("docker", built.args))
        assert isinstance(declared_container_name(audited.args), str)
