import pytest

from mcp_auditor.domain.container_name import Undecidable, declared_container_name


@pytest.mark.parametrize(
    ("args", "name"),
    [
        (["run", "-i", "--name", "srv", "img"], "srv"),
        (["run", "-i", "--name=srv", "img"], "srv"),
        (["run", "-i", "--rm", "img"], None),
        (["run", "-i", "img", "--name", "srv"], None),
        (["run", "-i", "--", "img", "--name", "srv"], None),
        (["run", "-e", "--name", "img"], None),
        (["run", "-it", "--name", "srv", "img"], "srv"),
        (["run", "-ie", "A=1", "--name", "srv", "img"], "srv"),
        (["run", "-eA=1", "-v=/a:/b", "--name", "srv", "img"], "srv"),
        (["run", "--network", "n", "--memory=4g", "--rm=false", "--name", "srv", "img"], "srv"),
        (["run", "--name", "srv", "--a-future-option", "img"], "srv"),
        (["run", "--name", "a", "--a-future-option", "x", "--name", "b", "img"], Undecidable.NAME),
        (["run", "--name", "srv", "--name=", "img"], None),
        (["run", "--a-future-option", "x", "--name", "srv", "img"], Undecidable.NAME),
        (["run", "-iZ", "--name", "srv", "img"], Undecidable.NAME),
        (["container", "run", "--name", "srv", "img"], None),
    ],
)
def test_declared_container_name(args: list[str], name: str | Undecidable | None):
    assert declared_container_name(args) == name
