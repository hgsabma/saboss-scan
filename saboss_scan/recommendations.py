from __future__ import annotations

from typing import Any


HEADER_RECOMMENDATIONS: dict[str, str] = {
    "strict-transport-security": "Aktivera HSTS så att webbläsare alltid använder HTTPS.",
    "content-security-policy": "Lägg till en Content-Security-Policy för att minska XSS-risk.",
    "x-frame-options": "Lägg till X-Frame-Options eller frame-ancestors i CSP för att minska clickjacking-risk.",
    "x-content-type-options": "Lägg till X-Content-Type-Options: nosniff.",
    "referrer-policy": "Lägg till Referrer-Policy, exempelvis strict-origin-when-cross-origin.",
    "permissions-policy": "Lägg till Permissions-Policy för att begränsa webbläsarfunktioner.",
}


def build_recommendations(results: dict[str, Any]) -> list[str]:
    """Create plain-language recommendations based on scan results."""
    recommendations: list[str] = []
    ssl_result = results.get("ssl", {})
    headers_result = results.get("headers", {})
    dns_result = results.get("dns", {})

    if not ssl_result.get("https"):
        recommendations.append("Aktivera HTTPS och installera ett giltigt SSL/TLS-certifikat.")
    elif not ssl_result.get("certificate_valid"):
        recommendations.append("Fixa SSL/TLS-certifikatet. Det verkar inte vara giltigt.")
    elif ssl_result.get("days_until_expiry") is not None and ssl_result["days_until_expiry"] < 30:
        recommendations.append("Förnya SSL/TLS-certifikatet snart. Det går ut inom 30 dagar.")

    for missing_header in headers_result.get("missing", []):
        recommendations.append(HEADER_RECOMMENDATIONS.get(missing_header, f"Lägg till headern {missing_header}."))

    if not dns_result.get("mx"):
        recommendations.append("Lägg till MX-records om domänen ska kunna ta emot e-post.")
    if not dns_result.get("spf"):
        recommendations.append("Lägg till SPF-record för att minska risken för e-postspoofing.")
    if not dns_result.get("dmarc"):
        recommendations.append("Lägg till DMARC-record för bättre skydd mot spoofing och phishing.")
    if not dns_result.get("dkim"):
        recommendations.append("Kontrollera DKIM. Scannern hittade ingen DKIM-record med vanliga selectors.")

    if not recommendations:
        recommendations.append("Bra jobbat. Inga stora grundproblem hittades i den här första scannen.")

    return recommendations
