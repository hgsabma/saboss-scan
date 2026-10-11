"""Make sure the scanner only talks to public internet addresses.

Validating the domain *name* (utils.normalize_domain) is not enough: anyone can
create a public domain whose DNS points to 127.0.0.1, a home router
(192.168.x.x) or a cloud metadata service (169.254.169.254). This module checks
the IP addresses a name actually resolves to.

Known limitation: the check and the later connection do two separate DNS
lookups, so a hostile DNS server could answer differently the second time
("DNS rebinding"). Before Saboss Scan runs as a web service, connections must
be pinned to the checked IP address.
"""
from __future__ import annotations

import ipaddress
import socket

from .utils import InvalidTargetError


class UnsafeTargetError(InvalidTargetError):
    """The domain resolves to an address that must not be scanned."""


def is_public_ip(address: str) -> bool:
    ip = ipaddress.ip_address(address.split("%")[0])  # drop IPv6 zone id, e.g. fe80::1%eth0
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        ip = ip.ipv4_mapped  # ::ffff:127.0.0.1 is really 127.0.0.1
    return ip.is_global and not ip.is_multicast


def resolve_addresses(hostname: str, port: int = 443) -> list[str]:
    """Return all IP addresses for a hostname using the system resolver.

    This is the same resolver that the TLS and HTTP checks use when they connect.
    Returns an empty list if the name cannot be resolved.
    """
    try:
        infos = socket.getaddrinfo(hostname, port, proto=socket.IPPROTO_TCP)
    except (socket.gaierror, UnicodeError):
        return []
    return sorted({info[4][0] for info in infos})


def ensure_public_addresses(hostname: str, addresses: list[str]) -> None:
    """Raise UnsafeTargetError if any of the given addresses is not public."""
    blocked = [address for address in addresses if not is_public_ip(address)]
    if blocked:
        raise UnsafeTargetError(
            f"'{hostname}' points to a private or reserved address ({', '.join(blocked)}) "
            "and cannot be scanned."
        )


def ensure_public_target(hostname: str) -> list[str]:
    """Raise UnsafeTargetError if the hostname resolves to a non-public address.

    A name that does not resolve at all is allowed through: the checks will then
    report it as "not checked" or "does not resolve".
    """
    addresses = resolve_addresses(hostname)
    ensure_public_addresses(hostname, addresses)
    return addresses
