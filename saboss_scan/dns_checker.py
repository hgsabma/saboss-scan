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
    text = record.to_text() if hasattr(record, "to_text") else str(record)
    return text.strip().strip('"')


def _resolve(domain: str, record_type: str, limit: int = 20) -> list[str]:
    dns_resolver = _import_dns()
    if dns_resolver is None:
        raise RuntimeError("Missing dependency: install dnspython with 'pip install -r requirements.txt'")

    resolver = dns_resolver.Resolver(configure=False)
    resolver.nameservers = PUBLIC_DNS_SERVERS
    resolver.timeout = 3
    resolver.lifetime = 6

    answers = resolver.resolve(domain, record_type, raise_on_no_answer=False)
    return [_record_to_text(record) for record in answers][:limit]


def _safe_resolve(domain: str, record_type: str) -> tuple[list[str], str | None]:
    try:
        return _resolve(domain, record_type), None
    except Exception as exc:
        return [], str(exc)


def _find_spf(txt_records: list[str]) -> list[str]:
    return [record for record in txt_records if "v=spf1" in record.lower()]


def _find_dmarc(domain: str) -> list[str]:
    records, _ = _safe_resolve(f"_dmarc.{domain}", "TXT")
    return [record for record in records if "v=dmarc1" in record.lower()]


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
    result["dmarc"] = _find_dmarc(domain)
    result["dkim"] = _find_dkim(domain)

    return result