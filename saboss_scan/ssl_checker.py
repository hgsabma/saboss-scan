from __future__ import annotations

import socket
import ssl
from datetime import datetime, timezone
from typing import Any


CERT_DATE_FORMAT = "%b %d %H:%M:%S %Y %Z"


def _name_to_text(name_parts: Any) -> str:
    """Convert certificate issuer/subject tuples into readable text."""
    try:
        return ", ".join(f"{key}={value}" for part in name_parts for key, value in part)
    except Exception:
        return str(name_parts)


def check_ssl(domain: str, timeout: int = 3) -> dict[str, Any]:
    """Check if a domain has a valid HTTPS certificate.

    This opens a TLS connection to port 443 and reads the certificate.
    It does not attack the site; it only performs a normal HTTPS handshake.
    """
    result: dict[str, Any] = {
        "https": False,
        "certificate_valid": False,
        "expires_at": None,
        "days_until_expiry": None,
        "issuer": None,
        "subject": None,
        "error": None,
    }

    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as secure_sock:
                cert = secure_sock.getpeercert()

        result["https"] = True
        result["certificate_valid"] = True
        result["issuer"] = _name_to_text(cert.get("issuer", []))
        result["subject"] = _name_to_text(cert.get("subject", []))

        not_after = cert.get("notAfter")
        if not_after:
            expires = datetime.strptime(not_after, CERT_DATE_FORMAT).replace(tzinfo=timezone.utc)
            now = datetime.now(timezone.utc)
            result["expires_at"] = expires.isoformat()
            result["days_until_expiry"] = max((expires - now).days, 0)

    except ssl.SSLCertVerificationError as exc:
        result["https"] = True
        result["certificate_valid"] = False
        result["error"] = f"Certificate verification failed: {exc}"
    except Exception as exc:
        result["error"] = str(exc)

    return result
