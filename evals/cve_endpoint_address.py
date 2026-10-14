"""Resolving an http_endpoint place's host to the address its sentinel binds.

A localhost name serves on the holder's loopback; an IPv4 literal binds that literal (adding a
loopback alias unless it already is loopback); a DNS name on a networked launch is a bridge
alias with no bound address; a DNS name on an isolated launch is served on a private /24 the
holder adds and the target resolves through an added host entry. The draft these resolvers
mutate is named structurally (`BindAddressDraft`), so this module stays free of the spec's
private draft type while `_SpecDraft` satisfies it.
"""

from ipaddress import AddressValueError, IPv4Address, IPv4Network
from typing import Protocol

from evals.cve_planting_base import PlantingHost

# The private /24 a name host without a network is served on: inside 10.0.0.0/8, outside
# Docker's default pools and outside 169.254.0.0/16.
RESERVED_NAME_BLOCK = IPv4Network("10.255.255.0/24")
_LOOPBACK = IPv4Network("127.0.0.0/8")
_NON_UNICAST_BLOCKS = (
    IPv4Network("0.0.0.0/8"),
    IPv4Network("224.0.0.0/4"),
    IPv4Network("240.0.0.0/4"),
)


class BindAddressDraft(Protocol):
    bind_addresses: set[str]
    address_setups: list[str]
    host_entries: list[tuple[str, str]]
    reserved_index: int


def endpoint_bind_address(
    entry_id: str, endpoint_host: str, host: PlantingHost, draft: BindAddressDraft
) -> str | None:
    if endpoint_host == "localhost":
        return "127.0.0.1"  # a loopback name: served on the holder's lo, no address setup
    literal = _as_ipv4(endpoint_host)
    if literal is not None:
        return _literal_bind_address(entry_id, literal, draft)
    if host.has_network:
        return None  # a DNS name on a launch with a network: a bridge alias, no holder
    return _name_host_bind_address(endpoint_host, draft)


def claim_bind_address(entry_id: str, bind_address: str | None, draft: BindAddressDraft) -> None:
    if bind_address is None:  # a bridge alias: only a holder-bound sentinel claims an address
        return
    if bind_address in draft.bind_addresses:  # two hosts can resolve to one holder address
        raise ValueError(f"{entry_id}: a second http_endpoint place on the same bind address")
    draft.bind_addresses.add(bind_address)


def _literal_bind_address(entry_id: str, literal: IPv4Address, draft: BindAddressDraft) -> str:
    if literal in RESERVED_NAME_BLOCK:
        raise ValueError(f"{entry_id}: an http_endpoint IP literal inside the reserved block")
    if any(literal in block for block in _NON_UNICAST_BLOCKS):
        raise ValueError(f"{entry_id}: an http_endpoint IP literal is not a unicast host address")
    if literal not in _LOOPBACK:
        draft.address_setups.append(str(literal))
    return str(literal)


def _name_host_bind_address(endpoint_host: str, draft: BindAddressDraft) -> str:
    draft.reserved_index += 1
    address = str(RESERVED_NAME_BLOCK.network_address + draft.reserved_index)
    draft.address_setups.append(address)
    draft.host_entries.append((endpoint_host, address))
    return address


def _as_ipv4(host: str) -> IPv4Address | None:
    try:
        return IPv4Address(host)
    except AddressValueError:
        return None
