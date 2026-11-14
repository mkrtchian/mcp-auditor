from mcp_auditor.adapters.docker import docker_client_env


def test_keeps_the_docker_client_variables():
    environ = {
        "DOCKER_HOST": "unix:///run/user/1000/docker.sock",
        "DOCKER_CONTEXT": "rootless",
        "DOCKER_CONFIG": "/home/alice/.docker",
        "DOCKER_TLS_VERIFY": "1",
        "DOCKER_CERT_PATH": "/home/alice/.docker/certs",
    }

    assert docker_client_env(environ) == environ


def test_drops_every_other_variable():
    environ = {"DOCKER_HOST": "unix:///var/run/docker.sock", "PATH": "/usr/bin", "HOME": "/root"}

    assert docker_client_env(environ) == {"DOCKER_HOST": "unix:///var/run/docker.sock"}


def test_omits_the_variables_the_environment_does_not_carry():
    assert docker_client_env({}) == {}
