from collections.abc import Iterable
from ipaddress import IPv4Address, ip_address
from pathlib import Path

from cryptography import x509
from cryptography.x509.oid import NameOID

from evals.cve.detection.targets import ACCEPTANCE_TARGETS
from evals.holdout_targets import HOLDOUT_TARGETS
from evals.nuisance_backends import BACKENDS
from evals.public_stand_ins import STAND_INS_DIRECTORY
from tests.unit.support.test_nuisance_committed_admission_given import the_committed_admission


def declared_stand_in_hosts() -> set[str]:
    targets = (*ACCEPTANCE_TARGETS, *HOLDOUT_TARGETS)
    declared = {host for target in targets for host in target.planting_host.public_names.stand_ins}
    admitted = {
        host
        for server in the_committed_admission().servers
        for host in server.host.public_names.stand_ins
    }
    backend_captures = {path.stem for path in _backend_served_in(STAND_INS_DIRECTORY, ".json")}
    return declared | admitted | backend_captures


def authority_hosts(directory: Path) -> set[str]:
    """Every captured host, plus every name a backend serves under TLS from a fixture leaf."""
    captured = {capture.stem for capture in directory.glob("*.json")}
    leaves = {
        path.stem
        for path in _backend_served_in(directory / "tls", ".pem")
        if path.name != "fixture-authority.pem" and not path.name.endswith("-key.pem")
    }
    return captured | leaves


def _backend_served_in(directory: Path, suffix: str) -> set[Path]:
    return {
        path
        for backend in BACKENDS.values()
        for path in backend.served
        if path.parent == directory and path.suffix == suffix
    }


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
