from __future__ import annotations

from typing import Any

COMMON_DKIM_SELECTORS = ["selector1", "selector2", "google", "default", "mail", "k1"]
PUBLIC_DNS_SERVERS = ["1.1.1.1", "8.8.8.8", "9.9.9.9"]


def _import_dns():
    try:
        import dns.resolver  # type: ignore

        return dns.resolver
    except ImportError:
        return None


def _record_to_text(record: Any) -> str:
    # TXT records can be split into several strings ("v=spf1 ..." "... -all").
    # They must be joined back together, otherwise long SPF/DKIM records break.
    if hasattr(record, "strings"):
        return b"".join(record.strings).decode("utf-8", errors="replace").strip()
    text = record.to_text() if hasattr(record, "to_text") else str(record)
    return text.strip().strip('"')


# Upper bound to keep reports a sane size. Must be generous: large companies
# often have 20+ TXT records (domain verifications), and the SPF record can be
# any one of them.
MAX_RECORDS = 200


def _resolve(dns_resolver: Any, name: str, record_type: str, limit: int = MAX_RECORDS) -> list[str]:
    resolver = dns_resolver.Resolver(configure=False)
    resolver.nameservers = PUBLIC_DNS_SERVERS
    resolver.timeout = 3
    resolver.lifetime = 6

    answers = resolver.resolve(name, record_type, raise_on_no_answer=False)
    return [_record_to_text(record) for record in answers][:limit]


def _safe_resolve(name: str, record_type: str) -> tuple[list[str], str | None]:
    """Return (records, error).

    A name that does not exist (NXDOMAIN) is a normal answer, not an error:
    for example most domains have no _dmarc record. Only real failures such
    as timeouts are reported as errors.
    """
    dns_resolver = _import_dns()
    if dns_resolver is None:
        return [], "Missing dependency: install dnspython with 'pip install -r requirements.txt'"

    try:
        return _resolve(dns_resolver, name, record_type), None
    except dns_resolver.NXDOMAIN:
        return [], None
    except dns_resolver.LifetimeTimeout:
        return [], "DNS lookup timed out."
    except dns_resolver.NoNameservers:
        return [], "DNS servers could not answer."
    except Exception as exc:
        return [], f"DNS lookup failed ({type(exc).__name__})."


def _find_spf(txt_records: list[str]) -> list[str]:
    return [record for record in txt_records if record.lower().startswith("v=spf1")]


def _find_dkim(domain: str) -> dict[str, list[str]]:
    found: dict[str, list[str]] = {}
    for selector in COMMON_DKIM_SELECTORS:
        records, _ = _safe_resolve(f"{selector}._domainkey.{domain}", "TXT")
        dkim_records = [record for record in records if "v=dkim1" in record.lower()]
        if dkim_records:
            found[selector] = dkim_records
    return found


def check_dns(domain: str) -> dict[str, Any]:
    result: dict[str, Any] = {
        "a": [],
        "aaaa": [],
        "mx": [],
        "txt": [],
        "spf": [],
        "dmarc": [],
        "dkim": {},
        "errors": {},
    }

    for key, record_type in [("a", "A"), ("aaaa", "AAAA"), ("mx", "MX"), ("txt", "TXT")]:
        records, error = _safe_resolve(domain, record_type)
        result[key] = records
        if error:
            result["errors"][key] = error

    result["spf"] = _find_spf(result["txt"])

    dmarc_records, dmarc_error = _safe_resolve(f"_dmarc.{domain}", "TXT")
    result["dmarc"] = [record for record in dmarc_records if record.lower().startswith("v=dmarc1")]
    if dmarc_error:
        result["errors"]["dmarc"] = dmarc_error

    result["dkim"] = _find_dkim(domain)

    return result
