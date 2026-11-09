from collections.abc import Callable
from dataclasses import dataclass

from evals.apify_backend import APIFY_BRIDGE, APIFY_RESPONDER_IMAGE, APIFY_SUFFIX_HOST
from evals.facebook_ads_backend import FACEBOOK_ADS_ATTACKER_HOST, FACEBOOK_ADS_BENIGN_HOST
from evals.nuisance_backends import BACKENDS
from evals.nuisance_fix_checks import cve_2026_10276_jenkins as jenkins
from evals.nuisance_fix_checks import cve_2026_19956_facebook_ads as facebook_ads
from evals.nuisance_fix_checks import cve_2026_46341_apify as apify
from evals.nuisance_fix_checks import cve_2026_61462_gitlab as gitlab
from evals.nuisance_fix_checks import cve_2026_77252_atlassian as atlassian

RESPONDER_ADDRESS = "198.18.9.77"


@dataclass(frozen=True)
class ResponderFixCheck:
    flaw: str
    backend: str
    responder_args: Callable[[str, str, str], list[str]]  # (name, nonce, address)
    server_args: Callable[[str, str], list[str]]  # (image, address)
    pointers: Callable[[str], list[str]]  # the server-specific entries for the address
    witness_variable: str = "WITNESS_NONCE"  # the responder environment variable holding it
    # Set when the responder is not a registered backend, read in place of the registry entry.
    network: str | None = None
    image: str | None = None

    @property
    def bridge(self) -> str:
        return self.network if self.network is not None else BACKENDS[self.backend].network

    @property
    def responder_image(self) -> str:
        return self.image if self.image is not None else BACKENDS[self.backend].image


RESPONDER_FIX_CHECKS = [
    ResponderFixCheck(
        apify.TARGET.flaw,
        "apify",
        apify.responder_args,
        apify.server_args,
        lambda address: [f"{APIFY_SUFFIX_HOST}:{address}"],
        network=APIFY_BRIDGE,
        image=APIFY_RESPONDER_IMAGE,
    ),
    ResponderFixCheck(
        atlassian.TARGET.flaw,
        "atlassian",
        atlassian.responder_args,
        atlassian.server_args,
        lambda address: [f"JIRA_URL=http://{address}", f"CONFLUENCE_URL=http://{address}"],
        "DEMO_SUMMARY",
    ),
    ResponderFixCheck(
        facebook_ads.TARGET.flaw,
        "facebook_ads",
        facebook_ads.responder_args,
        facebook_ads.server_args,
        lambda address: [
            f"{FACEBOOK_ADS_BENIGN_HOST}:{address}",
            f"{FACEBOOK_ADS_ATTACKER_HOST}:{address}",
        ],
    ),
    ResponderFixCheck(
        gitlab.TARGET.flaw,
        "gitlab",
        gitlab.responder_args,
        gitlab.server_args,
        lambda address: [f"GITLAB_API_URL=http://{address}/api/v4"],
    ),
    ResponderFixCheck(
        jenkins.TARGET.flaw,
        "jenkins",
        jenkins.responder_args,
        jenkins.server_args,
        lambda address: [f"JENKINS_URL=http://{address}"],
    ),
]
