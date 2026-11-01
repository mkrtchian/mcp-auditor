from evals.cve_planting import PlantedArgs
from evals.figma_backend import FIGMA_BRIDGE
from evals.nuisance_fix_checks.cve_2025_15061_figma import (
    AIM,
    INJECTED_FILE_KEY,
    server_args,
)


def test_injected_file_key_reads_the_witness_and_forges_a_figma_document():
    assert "cat /witness" in INJECTED_FILE_KEY
    assert "printf" in INJECTED_FILE_KEY
    assert "%s" in INJECTED_FILE_KEY


def test_aim_matches_the_injected_file_key():
    assert AIM.search(INJECTED_FILE_KEY)


def test_aim_does_not_match_the_benign_file_key():
    assert not AIM.search("abc123")


def _planted_args() -> PlantedArgs:
    return PlantedArgs(
        user=("--user", "65534:65534"),
        working_directory=("-w", "/"),
        env=(),
        mounts=("-v", "/tmp/w:/witness:ro"),
        hostname=(),
        network=("--network", "none"),
    )


def test_server_args_joins_the_figma_bridge_instead_of_the_planted_network():
    args = server_args("figma:local", _planted_args())

    assert "--network" in args
    index = args.index("--network")
    assert args[index + 1] == FIGMA_BRIDGE
    assert "none" not in args


def test_server_args_carries_the_figma_network_args():
    args = server_args("figma:local", _planted_args())

    assert "--add-host" in args
    assert "api.figma.com:198.18.6.2" in args
    assert any(arg.startswith("NODE_EXTRA_CA_CERTS=") for arg in args)
    assert any(arg.startswith("CURL_CA_BUNDLE=") for arg in args)


def test_server_args_ends_with_the_image_and_stdio_flag():
    args = server_args("figma:local", _planted_args())

    assert args[-2:] == ["figma:local", "--stdio"]


def test_server_args_includes_the_planted_witness_mount():
    args = server_args("figma:local", _planted_args())

    assert "-v" in args
    index = args.index("-v")
    assert args[index + 1] == "/tmp/w:/witness:ro"
