"""Domain OSINT: RDAP registration data, DNS resolution and IP attribution."""

from __future__ import annotations

from datetime import datetime, timezone

from ..httpclient import describe_error, fetch
from ..safety import BlockedTarget, inline, validate_domain


def _parse_date(value: str) -> datetime | None:
    for fmt in ("%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%dT%H:%M:%S.%fZ", "%Y-%m-%d"):
        try:
            parsed = datetime.strptime(value[:26] if "." in value else value, fmt)
            return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None


async def whois_lookup(domain: str) -> str:
    """Investigate a domain: RDAP registration, DNS records and hosting attribution.

    Highlights the signals that matter for phishing triage — registration age,
    registrar, nameservers, resolved addresses and hosting ASN. Newly
    registered domains are called out explicitly.

    Args:
        domain: Registrable domain name, e.g. example.com
    """
    try:
        name = validate_domain(domain)
    except BlockedTarget as exc:
        return f"❌ {exc}"

    out = f"## Domain OSINT — `{name}`\n\n"
    signals: list[str] = []

    # ── RDAP (the modern replacement for port-43 WHOIS) ───────────────────
    try:
        response, _ = await fetch(f"https://rdap.org/domain/{name}")
        if response.status_code == 404:
            out += "> Domain is not registered, or its TLD has no RDAP service.\n\n"
        elif response.status_code != 200:
            out += f"> RDAP returned HTTP {response.status_code}.\n\n"
        else:
            rdap = response.json()
            events = {e.get("eventAction"): e.get("eventDate", "") for e in rdap.get("events", [])}
            created_raw = events.get("registration", "")
            created = _parse_date(created_raw)

            registrar = "N/A"
            for entity in rdap.get("entities", []):
                if "registrar" in entity.get("roles", []):
                    vcard = (entity.get("vcardArray") or [[], []])[1]
                    registrar = next((v[3] for v in vcard if v and v[0] == "fn"), "N/A")
                    break

            nameservers = [ns.get("ldhName", "") for ns in rdap.get("nameservers", [])]
            statuses = rdap.get("status", [])

            out += "### Registration\n\n| Field | Value |\n|---|---|\n"
            out += f"| Registrar | {inline(registrar)} |\n"
            out += f"| Created | {created_raw[:10] or 'N/A'} |\n"
            out += f"| Updated | {events.get('last changed', 'N/A')[:10]} |\n"
            out += f"| Expires | {events.get('expiration', 'N/A')[:10]} |\n"
            out += f"| Status | {inline(', '.join(statuses)) if statuses else 'N/A'} |\n"
            out += f"| Nameservers | {inline(', '.join(nameservers), 200) if nameservers else 'none'} |\n\n"

            if created:
                age_days = (datetime.now(timezone.utc) - created).days
                out += f"**Domain age:** {age_days:,} days\n\n"
                if age_days < 30:
                    signals.append(
                        f"🔴 Registered {age_days} days ago. Most phishing and malware "
                        "domains are used within weeks of registration."
                    )
                elif age_days < 180:
                    signals.append(f"🟠 Registered {age_days} days ago — young enough to warrant caution.")

            if any("clienthold" in s.lower() or "serverhold" in s.lower() for s in statuses):
                signals.append("🔴 Domain is on registry/registrar hold — often a post-abuse takedown.")
    except Exception as exc:  # noqa: BLE001
        out += describe_error(exc) + "\n\n"

    # ── DNS over HTTPS ────────────────────────────────────────────────────
    records: dict[str, list[str]] = {}
    for rtype, code in (("A", 1), ("AAAA", 28), ("MX", 15), ("NS", 2), ("TXT", 16)):
        try:
            response, _ = await fetch(
                f"https://cloudflare-dns.com/dns-query?name={name}&type={rtype}",
                headers={"Accept": "application/dns-json"},
            )
            if response.status_code == 200:
                answers = response.json().get("Answer", []) or []
                records[rtype] = [a.get("data", "") for a in answers if a.get("type") == code]
        except Exception:  # noqa: BLE001 — a missing record type is not an error
            records[rtype] = []

    out += "### DNS\n\n"
    if any(records.values()):
        for rtype, values in records.items():
            if values:
                out += f"- **{rtype}:** {inline(', '.join(values), 300)}\n"
        out += "\n"
    else:
        out += "No records resolved. The domain may be parked, suspended or nonexistent.\n\n"

    spf = [t for t in records.get("TXT", []) if "v=spf1" in t.lower()]
    if not spf and records.get("MX"):
        signals.append("🟠 MX records exist but no SPF record — the domain is spoofable in email.")

    # ── IP attribution for the first A record ─────────────────────────────
    a_records = records.get("A", [])
    if a_records:
        ip = a_records[0]
        try:
            response, _ = await fetch(
                f"https://ip-api.com/json/{ip}?fields=status,country,regionName,city,isp,org,as,hosting,proxy"
            )
            if response.status_code == 200:
                geo = response.json()
                if geo.get("status") == "success":
                    out += f"### Hosting — {ip}\n\n| Field | Value |\n|---|---|\n"
                    out += f"| Location | {inline(geo.get('city'))}, {inline(geo.get('regionName'))}, {inline(geo.get('country'))} |\n"
                    out += f"| ISP | {inline(geo.get('isp'))} |\n"
                    out += f"| Organisation | {inline(geo.get('org'))} |\n"
                    out += f"| ASN | {inline(geo.get('as'), 160)} |\n\n"
                    if geo.get("proxy"):
                        signals.append("🟠 Fronted by a proxy, VPN or Tor exit — true origin is hidden.")
        except Exception as exc:  # noqa: BLE001
            out += describe_error(exc) + "\n\n"

    if signals:
        out += "### Risk signals\n\n" + "\n".join(f"- {s}" for s in signals) + "\n\n"

    out += (
        "> Registrant contact details are redacted by GDPR and by most registrars' "
        "privacy services, so their absence is not itself suspicious. Everything "
        "above is registrant-supplied or third-party data — corroborate before acting.\n"
    )
    return out
