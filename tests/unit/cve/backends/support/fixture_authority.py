from collections.abc import Sequence

from evals.cve.public_stand_ins import stand_in_files
from tests.unit.support.docker_argv import environment, mount_of

_AUTHORITY_PATH = "/etc/ssl/extra-ca.pem"
_SKIP_VERIFY_VARIABLES = ("NODE_TLS_REJECT_UNAUTHORIZED", "PYTHONHTTPSVERIFY")


def trusts_the_fixture_authority(args: Sequence[str], variable: str, host: str) -> None:
    env = environment(args)
    authority = stand_in_files(host).authority
    assert env[variable] == _AUTHORITY_PATH
    assert mount_of(args, _AUTHORITY_PATH) == f"{authority}:{_AUTHORITY_PATH}:ro"
    assert not [name for name in _SKIP_VERIFY_VARIABLES if name in env]
