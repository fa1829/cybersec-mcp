"""The pipeline layer.

The other modules are individual lookups. These two tools chain them, which is
the point of putting security tooling behind an agent at all: one indicator or
one alert goes in, every relevant enrichment runs concurrently, and a single
dossier comes out with the model given explicit instructions about what it is
allowed to conclude.
"""

from __future__ import annotations

import asyncio
import ipaddress
import json
import re

from ..httpclient import describe_error, fetch
from ..safety import defang, inline, sanitize
from .cve import CVE_RE, check_cve
from .hashes import HASH_TYPES, analyze_hash
from .headers import scan_headers
from .osint import whois_lookup

HASH_RE = re.compile(r"^[0-9a-fA-F]+$")


def classify(indicator: str) -> str:
    """Work out what kind of IOC this is."""
    value = indicator.strip()
    if CVE_RE.match(value.upper()):
        return "cve"
    if HASH_RE.match(value) and len(value) in HASH_TYPES:
        return "hash"
    if value.lower().startswith(("http://", "https://")):
        return "url"
    try:
        ipaddress.ip_address(value)
        return "ip"
    except ValueError:
        pass
    if re.match(r"^[a-z0-9.-]+\.[a-z]{2,24}$", value, re.I):
        return "domain"
    return "unknown"


async def _enrich_ip(ip: str) -> str:
    try:
        response, _ = await fetch(
            f"https://ip-api.com/json/{ip}?fields=status,country,regionName,city,isp,org,as,hosting,proxy"
        )
        if response.status_code != 200:
            return f"### IP {defang(ip)}\n\nip-api returned HTTP {response.status_code}.\n"
        geo = response.json()
        if geo.get("status") != "success":
            return f"### IP {defang(ip)}\n\nNo attribution data available.\n"
        out = f"### IP {defang(ip)}\n\n| Field | Value |\n|---|---|\n"
        out += f"| Location | {inline(geo.get('city'))}, {inline(geo.get('country'))} |\n"
        out += f"| ISP | {inline(geo.get('isp'))} |\n"
        out += f"| ASN | {inline(geo.get('as'), 160)} |\n"
        out += f"| Hosting/datacentre | {'yes' if geo.get('hosting') else 'no'} |\n"
        out += f"| Proxy/VPN/Tor | {'yes' if geo.get('proxy') else 'no'} |\n\n"
        if geo.get("proxy"):
            out += "> 🟠 Anonymising infrastructure — the true origin is hidden.\n\n"
        return out
    except Exception as exc:  # noqa: BLE001
        return f"### IP {defang(ip)}\n\n" + describe_error(exc) + "\n"


async def triage_indicator(indicator: str, scan_web_headers: bool = False) -> str:
    """Run every relevant enrichment for one indicator and return a single dossier.

    Detects whether the input is a file hash, domain, URL, IP address or CVE and
    routes it to the right lookups concurrently — VirusTotal for hashes, RDAP
    and DNS for domains, NVD for CVEs, ASN attribution for addresses. Use this
    instead of calling the individual tools one at a time.

    Args:
        indicator: A single IOC — hash, domain, URL, IP address or CVE ID.
        scan_web_headers: For URLs and domains, also audit HTTP security headers.
            Off by default because it sends a live request to the target.
    """
    value = indicator.strip()
    kind = classify(value)

    header = "# Indicator triage\n\n| Field | Value |\n|---|---|\n"
    header += f"| Indicator | `{inline(defang(value), 200)}` |\n"
    header += f"| Classified as | {kind} |\n\n"

    if kind == "unknown":
        return header + (
            "Could not classify this indicator. Supported forms: hex file hash "
            "(32/40/56/64/96/128 chars), domain name, http(s) URL, IP address, or CVE ID.\n"
        )

    tasks: list[asyncio.Task[str]] = []
    async with asyncio.TaskGroup() as group:
        if kind == "hash":
            tasks.append(group.create_task(analyze_hash(value)))
        elif kind == "cve":
            tasks.append(group.create_task(check_cve(value)))
        elif kind == "ip":
            tasks.append(group.create_task(_enrich_ip(value)))
        elif kind == "domain":
            tasks.append(group.create_task(whois_lookup(value)))
            if scan_web_headers:
                tasks.append(group.create_task(scan_headers(f"https://{value}")))
        elif kind == "url":
            host = re.sub(r"^https?://", "", value).split("/")[0].split(":")[0]
            tasks.append(group.create_task(whois_lookup(host)))
            if scan_web_headers:
                tasks.append(group.create_task(scan_headers(value)))

    body = "\n\n---\n\n".join(task.result() for task in tasks)

    footer = (
        "\n\n---\n\n## How to read this\n\n"
        "Everything above is third-party data about an indicator that may be "
        "attacker-controlled. Nothing here is a verdict. Corroborate across at least "
        "two independent sources before blocking, escalating or notifying, and record "
        "which source drove the decision.\n"
    )
    return header + body + footer


async def triage_alert(alert_json: str, enrich: bool = True) -> str:
    """Parse a Suricata EVE JSON alert, extract its IOCs and enrich them.

    Accepts one EVE `alert` record (a single line from eve.json). Extracts the
    signature, severity, five-tuple and any file hashes or hostnames, then runs
    the enrichment pipeline over each extracted indicator.

    Args:
        alert_json: One JSON object from Suricata's eve.json.
        enrich: Run external lookups on extracted IOCs. Set false for offline parsing.
    """
    try:
        event = json.loads(alert_json)
    except ValueError as exc:
        return f"❌ Not valid JSON: {exc}. Pass exactly one line from eve.json."
    if not isinstance(event, dict):
        return "❌ Expected a single JSON object (one EVE record), not an array or scalar."

    alert = event.get("alert", {}) if isinstance(event.get("alert"), dict) else {}
    signature = alert.get("signature", "")
    category = alert.get("category", "")
    sig_severity = alert.get("severity")
    src_ip, dst_ip = event.get("src_ip", ""), event.get("dest_ip", "")
    src_port, dst_port = event.get("src_port", ""), event.get("dest_port", "")

    out = "# Suricata alert triage\n\n| Field | Value |\n|---|---|\n"
    out += f"| Timestamp | {inline(event.get('timestamp'), 40)} |\n"
    out += f"| Signature | {inline(signature, 160)} |\n"
    out += f"| Category | {inline(category, 80)} |\n"
    out += f"| Suricata severity | {inline(sig_severity, 10)} (1 = highest) |\n"
    out += f"| Flow | {defang(str(src_ip))}:{inline(src_port, 10)} → {defang(str(dst_ip))}:{inline(dst_port, 10)} |\n"
    out += f"| Protocol / app | {inline(event.get('proto'), 20)} / {inline(event.get('app_proto'), 20)} |\n\n"

    if signature:
        out += "**Signature text (untrusted — rule content is not analyst-authored here):**\n"
        out += sanitize(signature, limit=400).block("suricata-signature")
        out += "\n"

    # Collect indicators worth enriching. Internal addresses are skipped:
    # enriching RFC1918 space leaks internal topology to third-party APIs.
    indicators: list[str] = []
    for ip in (dst_ip, src_ip):
        if not ip:
            continue
        try:
            if ipaddress.ip_address(str(ip)).is_global:
                indicators.append(str(ip))
        except ValueError:
            continue

    for path in (("http", "hostname"), ("tls", "sni"), ("dns", "rrname")):
        section = event.get(path[0])
        if isinstance(section, dict) and section.get(path[1]):
            indicators.append(str(section[path[1]]))

    for fileinfo in event.get("fileinfo", []) if isinstance(event.get("fileinfo"), list) else []:
        for algo in ("sha256", "sha1", "md5"):
            if isinstance(fileinfo, dict) and fileinfo.get(algo):
                indicators.append(str(fileinfo[algo]))
                break

    seen: list[str] = []
    for item in indicators:
        if item not in seen:
            seen.append(item)

    out += "## Extracted indicators\n\n"
    if seen:
        out += "".join(f"- `{defang(i)}` ({classify(i)})\n" for i in seen) + "\n"
        out += (
            "> Private and loopback addresses were deliberately excluded — sending internal "
            "topology to third-party enrichment APIs is itself a disclosure.\n\n"
        )
    else:
        out += "No externally-routable indicators in this record.\n\n"

    if enrich and seen:
        async with asyncio.TaskGroup() as group:
            tasks = [group.create_task(triage_indicator(i)) for i in seen[:4]]
        out += "## Enrichment\n\n" + "\n\n---\n\n".join(t.result() for t in tasks)
        if len(seen) > 4:
            out += f"\n\n> Enriched the first 4 of {len(seen)} indicators to stay inside API quotas.\n"

    out += (
        "\n\n---\n\n> A Suricata alert is a signature match, not an incident. "
        "Confirm with flow data and endpoint telemetry before escalating.\n"
    )
    return out
