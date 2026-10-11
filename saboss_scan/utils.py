from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlparse

MAX_DOMAIN_LENGTH = 253
ALLOWED_SCHEMES = {"http", "https"}
ALLOWED_PORTS = {None, 80, 443}

# One DNS label: letters, digits and hyphens, 1-63 characters,
# not starting or ending with a hyphen.
LABEL_PATTERN = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")

# Names that never point to a public website (RFC 6761, RFC 8375 and common
# internal conventions). Scanning them could reach the user's own network.
BLOCKED_SUFFIXES = (
    "localhost",
    "local",
    "internal",
    "intranet",
    "lan",
    "home.arpa",
    "arpa",
    "test",
    "invalid",
    "example",
    "onion",
)


class InvalidTargetError(ValueError):
    """Raised when user input is not a public domain we are willing to scan."""


def _is_ip_address(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def normalize_domain(value: str) -> str:
    """Turn user input into a validated public hostname.

    Examples:
        "https://Example.com/path" -> "example.com"
        "www.example.com"          -> "www.example.com"
        "bücher.de"                -> "xn--bcher-kva.de"

    Raises InvalidTargetError for empty input, IP addresses, internal names
    such as "localhost", and anything that is not a valid domain name.
    """
    cleaned = value.strip().lower()
    if not cleaned:
        raise InvalidTargetError("Domain cannot be empty.")

    if "://" not in cleaned:
        cleaned = "https://" + cleaned

    try:
        parsed = urlparse(cleaned)
        port = parsed.port
    except ValueError:
        raise InvalidTargetError(f"Could not read a domain from: {value!r}") from None

    if parsed.scheme not in ALLOWED_SCHEMES:
        raise InvalidTargetError("Only http:// and https:// addresses are supported.")
    if parsed.username is not None or parsed.password is not None:
        raise InvalidTargetError("Addresses containing a username or password are not allowed.")
    if port not in ALLOWED_PORTS:
        raise InvalidTargetError("Custom ports are not supported. Saboss Scan checks ports 80 and 443.")

    hostname = (parsed.hostname or "").rstrip(".")
    if not hostname:
        raise InvalidTargetError(f"Could not read a domain from: {value!r}")

    if _is_ip_address(hostname):
        raise InvalidTargetError("Please enter a domain name, not an IP address.")

    # Convert international names such as "bücher.de" to their ASCII form.
    try:
        hostname = hostname.encode("idna").decode("ascii")
    except UnicodeError:
        raise InvalidTargetError(f"Not a valid domain name: {value!r}") from None

    if len(hostname) > MAX_DOMAIN_LENGTH:
        raise InvalidTargetError("Domain name is too long.")

    for suffix in BLOCKED_SUFFIXES:
        if hostname == suffix or hostname.endswith("." + suffix):
            raise InvalidTargetError(
                f"'{hostname}' is a local or reserved name and cannot be scanned."
            )

    labels = hostname.split(".")
    if len(labels) < 2:
        raise InvalidTargetError("Please enter a full domain name, for example example.com.")
    if not all(LABEL_PATTERN.match(label) for label in labels):
        raise InvalidTargetError(f"Not a valid domain name: {value!r}")
    if labels[-1].isdigit():
        raise InvalidTargetError(f"Not a valid domain name: {value!r}")

    return hostname
