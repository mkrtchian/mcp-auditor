from typing import Any

import pytest
import yaml

from evals.cve.detection.targets import ACCEPTANCE_TARGETS
from evals.cve.images import COMPOSE_FILE
from evals.detection_preflight import expected_services, main


def test_the_printed_services_are_compose_services_and_no_holdout_one(
    capsys: pytest.CaptureFixture[str],
):
    compose_services: dict[str, Any] = yaml.safe_load(COMPOSE_FILE.read_text())["services"]

    main()

    printed = capsys.readouterr().out.split()
    assert printed == list(expected_services(ACCEPTANCE_TARGETS))
    assert set(printed) <= compose_services.keys()
    assert not [service for service in printed if service.startswith("holdout-")]
