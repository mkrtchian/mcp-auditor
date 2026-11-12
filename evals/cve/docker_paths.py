from pathlib import Path

DOCKER_DIRECTORY = Path(__file__).parents[1] / "docker"


def image_dockerfile(name: str, docker_directory: Path = DOCKER_DIRECTORY) -> Path:
    return docker_directory / f"Dockerfile.{name}"
