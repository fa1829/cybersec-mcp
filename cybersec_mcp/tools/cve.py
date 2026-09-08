"""CVE lookup against the NIST National Vulnerability Database."""

from __future__ import annotations

import re

from .. import config
from ..httpclient import cache_get, cache_put, describe_error, fetch
from ..safety import sanitize

CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,7}$")

SEVERITY_ICON = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢", "NONE": "⚪"}


def _pick_cvss(metrics: dict) -> tuple[str, dict]:
    for key, label in (
        ("cvssMetricV40", "CVSS 4.0"),
        ("cvssMetricV31", "CVSS 3.1"),
        ("cvssMetricV30", "CVSS 3.0"),
        ("cvssMetricV2", "CVSS 2.0"),
    ):
        entries = metrics.get(key) or []
        if entries:
            return label, entries[0]
    return "", {}


async def check_cve(cve_id: str) -> str:
    """Look up a CVE in the NIST NVD: CVSS score, exploitability metrics and references.

    Returns the base score and vector, the attack prerequisites (network
    reachability, privileges, user interaction) that decide real-world
    priority, and NVD's published/modified dates.

    Args:
        cve_id: CVE identifier such as CVE-2021-44228.
    """
    cid = cve_id.strip().upper()
    if not CVE_RE.match(cid):
        return f"❌ `{cid[:40]}` is not a valid CVE ID. Expected the form CVE-2021-44228."

    cache_key = f"nvd:{cid}"
    cached = cache_get(cache_key)
    if cached:
        return cached + "\n> 🗃️ Served from local cache.\n"

    headers = {"apiKey": config.NVD_API_KEY} if config.NVD_API_KEY else {}
    try:
        response, _ = await fetch(
            f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cid}", headers=headers
        )
    except Exception as exc:  # noqa: BLE001
        return describe_error(exc)

    if response.status_code == 403:
        return (
            "⏳ NVD returned HTTP 403, which in practice means rate limiting. "
            "Unauthenticated clients get 5 requests per 30 seconds. "
            "Request a free key at https://nvd.nist.gov/developers/request-an-api-key "
            "and set `NVD_API_KEY`."
        )
    if response.status_code != 200:
        return f"⚠️ NVD returned HTTP {response.status_code} for {cid}."

    vulnerabilities = response.json().get("vulnerabilities", [])
    if not vulnerabilities:
        return f"## {cid}\n\nNot present in NVD. It may be reserved, rejected, or too recent to be enriched.\n"

    vuln = vulnerabilities[0].get("cve", {})
    description = next(
        (d["value"] for d in vuln.get("descriptions", []) if d.get("lang") == "en"),
        "No description published.",
    )

    label, metric = _pick_cvss(vuln.get("metrics", {}))
    data = metric.get("cvssData", {})
    score = data.get("baseScore", "N/A")
    severity = str(data.get("baseSeverity") or metric.get("baseSeverity") or "N/A").upper()
    icon = SEVERITY_ICON.get(severity, "⚪")

    status = str(vuln.get("vulnStatus", "")).strip()
    published = (vuln.get("published") or "N/A")[:10]
    modified = (vuln.get("lastModified") or "N/A")[:10]

    out = f"## {cid}\n\n"
    out += "| Field | Value |\n|---|---|\n"
    out += f"| Severity | {icon} {severity} ({label or 'no CVSS published'}) |\n"
    out += f"| Base score | {score} / 10 |\n"
    out += f"| Vector | `{data.get('vectorString', 'N/A')}` |\n"
    out += f"| Attack vector | {data.get('attackVector', 'N/A')} |\n"
    out += f"| Attack complexity | {data.get('attackComplexity', 'N/A')} |\n"
    out += f"| Privileges required | {data.get('privilegesRequired', 'N/A')} |\n"
    out += f"| User interaction | {data.get('userInteraction', 'N/A')} |\n"
    out += f"| NVD status | {status or 'N/A'} |\n"
    out += f"| Published / modified | {published} / {modified} |\n\n"

    if status.lower() in {"awaiting analysis", "received", "undergoing analysis"}:
        out += (
            "> ⚠️ NVD has not finished analysing this CVE. Scores and affected-version "
            "data may be missing or change. Check the vendor advisory directly.\n\n"
        )

    if str(data.get("attackVector", "")).upper() == "NETWORK" and str(
        data.get("privilegesRequired", "")
    ).upper() == "NONE":
        out += (
            "> 🔥 Network-reachable with no privileges required. This is the profile that "
            "gets mass-scanned within days of a public PoC — prioritise on exposure, "
            "not on the base score alone.\n\n"
        )

    out += "### Description\n"
    out += sanitize(description, limit=1200).block("nvd-description")
    out += "\n"

    references = [r.get("url", "") for r in vuln.get("references", [])][:6]
    if references:
        out += "### References\n\n" + "\n".join(f"- {u}" for u in references if u) + "\n\n"
    out += f"**NVD record:** https://nvd.nist.gov/vuln/detail/{cid}\n\n"
    out += (
        "> CVSS measures inherent severity, not your risk. Cross-check CISA KEV "
        "(https://www.cisa.gov/known-exploited-vulnerabilities-catalog) and EPSS "
        "(https://www.first.org/epss/) for whether it is actually being exploited.\n"
    )

    cache_put(cache_key, out)
    return out
