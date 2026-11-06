import json
from collections.abc import Iterable
from ipaddress import IPv4Address, ip_address
from pathlib import Path

from cryptography import x509
from cryptography.x509.oid import NameOID

from evals.apify_backend import API_HOST
from evals.cve_targets import CVE_TARGETS
from evals.holdout_targets import HOLDOUT_TARGETS

# Hosts whose capture is committed before the target declaring it is vested.
PENDING_STAND_IN_HOSTS = frozenset(
    {
        "w3challs.com",  # CVE-2026-2130
        "html.duckduckgo.com",  # CVE-2026-42260
        "api.github.com",  # CVE-2025-53818
        "example-org.my.salesforce.com",  # CVE-2026-26029
        "45.55.0.10",  # CVE-2025-65719
        "rds.us-east-1.amazonaws.com",  # CVE-2026-85787, CVE-2026-85788
        "secretsmanager.us-east-1.amazonaws.com",  # CVE-2026-85787, CVE-2026-85788
    }
)


def declared_stand_in_hosts() -> set[str]:
    return target_declared_hosts() | {API_HOST} | PENDING_STAND_IN_HOSTS


def target_declared_hosts() -> set[str]:
    targets = (*CVE_TARGETS, *HOLDOUT_TARGETS)
    return {host for target in targets for host in target.planting_host.public_names.stand_ins}


def committed_https_hosts(directory: Path) -> set[str]:
    hosts: set[str] = set()
    for capture in directory.glob("*.json"):
        routes = json.loads(capture.read_text())["routes"]
        if any(route["scheme"] == "https" for route in routes):
            hosts.add(capture.stem)
    return hosts


def is_ip_literal(host: str) -> bool:
    try:
        ip_address(host)
    except ValueError:
        return False
    return True


def host_subtree(host: str) -> str:
    return f"{IPv4Address(host)}/32" if is_ip_literal(host) else host


def committed_authority_constraints(directory: Path) -> tuple[bool, set[str], set[str]]:
    """Critical flag, permitted and excluded subtrees (DNS names, IP networks in CIDR form)."""
    authority = directory / "tls" / "fixture-authority.pem"
    if not authority.exists():
        return True, set(), set()
    certificate = x509.load_pem_x509_certificate(authority.read_bytes())
    extension = certificate.extensions.get_extension_for_class(x509.NameConstraints)
    return (
        extension.critical,
        _subtree_names(extension.value.permitted_subtrees),
        _subtree_names(extension.value.excluded_subtrees),
    )


def committed_leaf_names(directory: Path) -> dict[str, set[str]]:
    """Each leaf's subject alternative names, DNS names and IP addresses alike."""
    leaves: dict[str, set[str]] = {}
    for certificate_path, certificate in _committed_leaves(directory):
        names = certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        dns = names.value.get_values_for_type(x509.DNSName)
        addresses = names.value.get_values_for_type(x509.IPAddress)
        leaves[certificate_path.name] = {*dns, *(str(address) for address in addresses)}
    return leaves


def committed_leaf_common_names(directory: Path) -> dict[str, list[str]]:
    return {
        path.name: [
            str(attribute.value)
            for attribute in certificate.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        ]
        for path, certificate in _committed_leaves(directory)
    }


def _committed_leaves(directory: Path) -> list[tuple[Path, x509.Certificate]]:
    return [
        (path, x509.load_pem_x509_certificate(path.read_bytes()))
        for path in (directory / "tls").glob("*.pem")
        if path.name != "fixture-authority.pem" and not path.name.endswith("-key.pem")
    ]


def _subtree_names(subtrees: Iterable[x509.GeneralName] | None) -> set[str]:
    names: set[str] = set()
    for subtree in subtrees or ():
        if isinstance(subtree, x509.DNSName):
            names.add(subtree.value)
        elif isinstance(subtree, x509.IPAddress):
            names.add(str(subtree.value))
    return names
