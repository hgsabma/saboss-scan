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


def check_ssl(domain: str, timeout: int = 5) -> dict[str, Any]:
    """Check if a domain has a valid HTTPS certificate.

    This opens a TLS connection to port 443 and reads the certificate.
    It does not attack the site; it only performs a normal HTTPS handshake.

    error_type tells the findings layer *why* a check failed:
        certificate  HTTPS works but the certificate is not trusted
        tls          the TLS handshake failed (e.g. outdated protocol)
        refused      nothing is listening on port 443
        dns          the name could not be resolved
        timeout      no answer in time (cannot tell if HTTPS exists)
        network      another network problem
    """
    result: dict[str, Any] = {
        "https": False,
        "certificate_valid": False,
        "tls_version": None,
        "expires_at": None,
        "days_until_expiry": None,
        "issuer": None,
        "subject": None,
        "error": None,
        "error_type": None,
    }

    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as secure_sock:
                cert = secure_sock.getpeercert()
                result["tls_version"] = secure_sock.version()

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

    # Order matters: the more specific exception types must come first.
    except ssl.SSLCertVerificationError as exc:
        result["https"] = True
        result["error_type"] = "certificate"
        result["error"] = f"Certificate verification failed: {exc.verify_message}"
    except ssl.SSLError as exc:
        result["error_type"] = "tls"
        # .reason is only set when the error comes from OpenSSL itself.
        reason = getattr(exc, "reason", None) or "unknown reason"
        result["error"] = f"TLS handshake failed: {reason}"
    except socket.gaierror:
        result["error_type"] = "dns"
        result["error"] = "The domain name could not be resolved."
    except TimeoutError:
        result["error_type"] = "timeout"
        result["error"] = f"No answer on port 443 within {timeout} seconds."
    except ConnectionRefusedError:
        result["error_type"] = "refused"
        result["error"] = "The server refused connections on port 443."
    except OSError as exc:
        result["error_type"] = "network"
        result["error"] = f"Network error ({type(exc).__name__})."

    return result
