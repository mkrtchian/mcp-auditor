import pytest

from mcp_auditor.domain.container_name import (
    Undecidable,
    declared_container_name,
    environment_names_passed,
    is_declared_container,
)


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


@pytest.mark.parametrize(
    ("args", "names", "env_file"),
    [
        (["run", "img"], set[str](), False),
        (["run", "-e", "A", "img"], {"A"}, False),
        (["run", "-e", "A=1", "img"], {"A"}, False),
        (["run", "--env", "A", "img"], {"A"}, False),
        (["run", "--env", "A=1", "img"], {"A"}, False),
        (["run", "--env=A", "img"], {"A"}, False),
        (["run", "--env=A=1", "img"], {"A"}, False),
        (["run", "-e", "A", "--env=B", "img"], {"A", "B"}, False),
        (["run", "--env-file", "f", "img"], set[str](), True),
        (["run", "--env-file=f", "img"], set[str](), True),
        (["run", "img", "-e"], set[str](), False),
        (["run", "-eA=1", "img"], {"A"}, False),
        (["run", "-e=A", "img"], {"A"}, False),
        (["run", "-ie", "A", "img"], {"A"}, False),
        (["run", "-ieA", "img"], {"A"}, False),
        (["run", "--env-file", "f", "img", "srv", "-v", "-e", "A"], {"A"}, True),
    ],
)
def test_environment_names_passed(args: list[str], names: set[str], env_file: bool):
    assert environment_names_passed(args) == (frozenset(names), env_file)


def test_a_docker_run_command_is_a_declared_container():
    assert is_declared_container("docker", ("run", "img"))
    assert is_declared_container("docker", ["run", "img"])


def test_other_container_spellings_are_not_declared_containers():
    assert not is_declared_container("docker", ["container", "run"])
    assert not is_declared_container("podman", ["run"])
    assert not is_declared_container("docker", [])
