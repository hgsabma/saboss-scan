from __future__ import annotations

from urllib.parse import urlparse


def normalize_domain(value: str) -> str:
    """Return only the hostname part from user input.

    Examples:
        "https://example.com/path" -> "example.com"
        "example.com" -> "example.com"
    """
    cleaned = value.strip().lower()
    if not cleaned:
        raise ValueError("Domain cannot be empty")

    if "://" not in cleaned:
        cleaned = "https://" + cleaned

    parsed = urlparse(cleaned)
    hostname = parsed.hostname
    if not hostname:
        raise ValueError(f"Could not read a domain from: {value}")

    return hostname.removeprefix("www.")
