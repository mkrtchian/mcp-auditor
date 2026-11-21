import pytest

from mcp_auditor.domain.container_name import Undecidable, declared_container_name


@pytest.mark.parametrize(
    ("args", "name"),
    [
        pytest.param(["run", "-i", "--name", "srv", "img"], "srv", id="name as a separate value"),
        pytest.param(["run", "-i", "--name=srv", "img"], "srv", id="name joined by an equals sign"),
        pytest.param(["run", "-i", "--rm", "img"], None, id="no name"),
        pytest.param(
            ["run", "-i", "img", "--name", "srv"],
            None,
            id="a name after the image belongs to the server",
        ),
        pytest.param(
            ["run", "-i", "--", "img", "--name", "srv"],
            None,
            id="a name after the end of options belongs to the server",
        ),
        pytest.param(
            ["run", "-e", "--name", "img"], None, id="-e swallows a following --name as its value"
        ),
        pytest.param(
            ["run", "-it", "--name", "srv", "img"],
            "srv",
            id="a group of short flags takes no value",
        ),
        pytest.param(
            ["run", "-ie", "A=1", "--name", "srv", "img"],
            "srv",
            id="a group ending in a valued short option takes the next argument",
        ),
        pytest.param(
            ["run", "-eA=1", "-v=/a:/b", "--name", "srv", "img"],
            "srv",
            id="a valued short option takes the rest of its group",
        ),
        pytest.param(
            ["run", "--network", "n", "--memory=4g", "--rm=false", "--name", "srv", "img"],
            "srv",
            id="known long options are skipped with or without their value joined",
        ),
        pytest.param(
            ["run", "--name", "srv", "--a-future-option", "img"],
            "srv",
            id="an unknown option after the name keeps the name",
        ),
        pytest.param(
            ["run", "--name", "a", "--a-future-option", "x", "--name", "b", "img"],
            Undecidable.NAME,
            id="an unknown option before a second name makes the name undecidable",
        ),
        pytest.param(
            ["run", "--name", "srv", "--name=", "img"], None, id="--name= clears the name"
        ),
        pytest.param(
            ["run", "--a-future-option", "x", "--name", "srv", "img"],
            Undecidable.NAME,
            id="an unknown option before the name makes the name undecidable",
        ),
        pytest.param(
            ["run", "-iZ", "--name", "srv", "img"],
            Undecidable.NAME,
            id="an unknown letter in a short group makes the name undecidable",
        ),
        pytest.param(
            ["container", "run", "--name", "srv", "img"], None, id="container run is not read"
        ),
    ],
)
def test_declared_container_name(args: list[str], name: str | Undecidable | None):
    assert declared_container_name(args) == name
