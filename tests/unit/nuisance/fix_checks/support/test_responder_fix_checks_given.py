from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from evals.cve.backends.apify import APIFY_BRIDGE
from evals.cve.backends.atlassian import ATLASSIAN_BRIDGE, ATLASSIAN_RESPONDER_IMAGE
from evals.cve.backends.facebook_ads import (
    FACEBOOK_ADS_BENIGN_HOST,
    FACEBOOK_ADS_BRIDGE,
    FACEBOOK_ADS_RESPONDER_IP,
)
from evals.cve.backends.gitlab_responder import GITLAB_BRIDGE, GITLAB_RESPONDER_IMAGE
from evals.cve.nuisance.fix_checks import cve_2026_19956_facebook_ads as facebook_ads
from evals.cve.nuisance.fix_checks import cve_2026_46341_apify as apify
from evals.cve.nuisance.fix_checks import cve_2026_61462_gitlab as gitlab
from evals.cve.nuisance.fix_checks import cve_2026_77252_atlassian as atlassian

RESPONDER_ADDRESS = "198.18.9.77"


@dataclass(frozen=True)
class ResponderFixCheck:
    flaw: str
    responder_args: Callable[[str, str, str], list[str]]  # (name, witness, address)
    server_args: Callable[[str, str], list[str]]  # (image, address)
    pointers: Callable[[str], list[str]]  # the server-specific entries for the address
    bridge: str
    responder_image: str
    witness_variable: str = "WITNESS_NONCE"  # the responder environment variable holding it


RESPONDER_FIX_CHECKS = [
    ResponderFixCheck(
        apify.FIXTURE.flaw,
        apify.responder_args,
        apify.server_args,
        lambda address: [f"{apify.APIFY_SUFFIX_HOST}:{address}"],
        bridge=APIFY_BRIDGE,
        responder_image=apify.APIFY_RESPONDER_IMAGE,
    ),
    ResponderFixCheck(
        atlassian.FIXTURE.flaw,
        atlassian.responder_args,
        atlassian.server_args,
        lambda address: [f"JIRA_URL=http://{address}", f"CONFLUENCE_URL=http://{address}"],
        bridge=ATLASSIAN_BRIDGE,
        responder_image=ATLASSIAN_RESPONDER_IMAGE,
        witness_variable="DEMO_SUMMARY",
    ),
    ResponderFixCheck(
        facebook_ads.FIXTURE.flaw,
        facebook_ads.sentinel_args,
        lambda image, address: facebook_ads.server_args(image, address, Path("/bundle.pem")),
        # The graph host stays on the run's responder, the attacker host goes to the sentinel.
        lambda address: [
            f"{FACEBOOK_ADS_BENIGN_HOST}:{FACEBOOK_ADS_RESPONDER_IP}",
            f"{facebook_ads.ATTACKER_HOST}:{address}",
        ],
        bridge=FACEBOOK_ADS_BRIDGE,
        responder_image=facebook_ads.SENTINEL_IMAGE,
    ),
    ResponderFixCheck(
        gitlab.FIXTURE.flaw,
        gitlab.responder_args,
        gitlab.server_args,
        lambda address: [f"GITLAB_API_URL=http://{address}/api/v4"],
        bridge=GITLAB_BRIDGE,
        responder_image=GITLAB_RESPONDER_IMAGE,
    ),
]
