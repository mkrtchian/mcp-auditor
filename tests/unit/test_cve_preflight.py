from collections.abc import Callable
from typing import Any

import pytest
import yaml

from evals.closed_network import ClosedNetworkUnsupported
from evals.cve_images import COMPOSE_FILE, dockerfile_fingerprint
from evals.cve_planting import SENTINEL_SERVICE
from evals.cve_planting_base import STAND_IN_SERVICE
from evals.cve_preflight import (
    PreflightDocker,
    expected_services,
    main,
    preflight_ok,
    vulnerable_services,
)
from evals.cve_targets import CVE_TARGETS, image_tag
from tests.fakes.image_store import FakeImageStore

FETCH_ID = "CVE-2025-65513"


def _a_daemon_closing_networks() -> None:
    pass


def _a_daemon_that_cannot_close_a_network() -> None:
    raise ClosedNetworkUnsupported("invalid gateway mode: isolated")


def _a_store_with_one_stale(stale: str, *, build_error: str | None = None) -> FakeImageStore:
    labels: dict[str, str | None] = {
        image_tag(service): dockerfile_fingerprint(service)
        for service in expected_services(CVE_TARGETS)
    }
    labels[image_tag(stale)] = "a-foreign-fingerprint"
    return FakeImageStore(labels, build_error=build_error)


def _a_docker(
    store: FakeImageStore,
    *,
    ready: bool = True,
    enforces_pids_limit: bool = True,
    check_closed_networks: Callable[[], None] = _a_daemon_closing_networks,
) -> PreflightDocker:
    return PreflightDocker(
        ready=lambda: ready,
        enforces_pids_limit=lambda: enforces_pids_limit,
        check_closed_networks=check_closed_networks,
        images=store,
    )


def test_the_preflight_rebuilds_a_stale_image_and_names_it(capsys: pytest.CaptureFixture[str]):
    stale = CVE_TARGETS[0].patched_image
    store = _a_store_with_one_stale(stale)

    ok = preflight_ok(_a_docker(store))

    assert ok
    assert store.builds == [[stale]]
    assert stale in capsys.readouterr().out


def test_the_preflight_fails_and_names_the_service_whose_rebuild_fails(
    capsys: pytest.CaptureFixture[str],
):
    stale = CVE_TARGETS[0].patched_image
    store = _a_store_with_one_stale(stale, build_error="no space left on device")

    ok = preflight_ok(_a_docker(store))

    assert not ok
    assert stale in capsys.readouterr().out


def test_the_preflight_fails_on_a_daemon_that_cannot_close_a_network_before_any_image(
    capsys: pytest.CaptureFixture[str],
):
    store = _a_store_with_one_stale(CVE_TARGETS[0].patched_image)

    ok = preflight_ok(_a_docker(store, check_closed_networks=_a_daemon_that_cannot_close_a_network))

    out = capsys.readouterr().out
    assert not ok
    assert store.builds == []
    assert "invalid gateway mode: isolated" in out
    assert "Docker Engine 28.0 or later is required" in out


def test_the_preflight_fails_on_an_unreachable_daemon_before_any_image(
    capsys: pytest.CaptureFixture[str],
):
    store = _a_store_with_one_stale(CVE_TARGETS[0].patched_image)

    ok = preflight_ok(_a_docker(store, ready=False))

    assert not ok
    assert store.builds == []
    assert "Docker daemon unreachable" in capsys.readouterr().out


def test_the_preflight_warns_and_still_passes_on_a_daemon_that_does_not_enforce_the_pids_limit(
    capsys: pytest.CaptureFixture[str],
):
    store = _a_store_with_one_stale(CVE_TARGETS[0].patched_image)

    ok = preflight_ok(_a_docker(store, enforces_pids_limit=False))

    assert ok
    assert "cannot enforce --pids-limit" in capsys.readouterr().out


def test_expected_services_keeps_the_sentinel_with_the_fetch_target_filtered_out():
    without_fetch = [target for target in CVE_TARGETS if target.cve_id != FETCH_ID]

    assert SENTINEL_SERVICE in expected_services(without_fetch)
    assert SENTINEL_SERVICE not in vulnerable_services(without_fetch)


def test_expected_services_carry_the_stand_in_only_while_a_target_declares_one():
    without_fetch = [target for target in CVE_TARGETS if target.cve_id != FETCH_ID]

    assert STAND_IN_SERVICE in expected_services(CVE_TARGETS)
    assert STAND_IN_SERVICE not in expected_services(without_fetch)


def test_the_printed_services_are_compose_services_and_no_holdout_one(
    capsys: pytest.CaptureFixture[str],
):
    compose_services: dict[str, Any] = yaml.safe_load(COMPOSE_FILE.read_text())["services"]

    main()

    printed = capsys.readouterr().out.split()
    assert printed == list(expected_services(CVE_TARGETS))
    assert set(printed) <= compose_services.keys()
    assert not [service for service in printed if service.startswith("holdout-")]
