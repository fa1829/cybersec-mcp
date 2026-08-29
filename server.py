#!/usr/bin/env python3
"""
CyberSec MCP Server v1.0.0
===========================
An information-security focused MCP server exposing 7 tools:

  1. analyze_hash        — Identify hash type + VirusTotal reputation
  2. check_cve           — NVD/NIST CVE lookup with CVSS details
  3. scan_headers        — HTTP security-header audit
  4. whois_lookup        — RDAP WHOIS + passive DNS + IP geolocation
  5. decode_payload      — Base64 / Hex / URL / ROT13 decoder
  6. password_strength   — NIST 800-63b password analysis (local only)
  7. generate_threat_report — Structured threat-intel report generator
"""

import asyncio
import base64
import hashlib
import json
import math
import os
import re
import sys
from datetime import datetime, timezone
from urllib.parse import unquote

import httpx
from mcp.server.fastmcp import FastMCP

# ─────────────────────────────────────────────
# Init
# ─────────────────────────────────────────────
VT_API_KEY = os.environ.get("VIRUSTOTAL_API_KEY", "")

mcp = FastMCP("cybersec-mcp")

TIMEOUT = httpx.Timeout(12.0)


async def http_get(url: str, headers: dict | None = None) -> httpx.Response:
    async with httpx.AsyncClient(timeout=TIMEOUT, follow_redirects=True) as client:
        return await client.get(url, headers=headers or {})


# ─────────────────────────────────────────────
# TOOL 1 — analyze_hash
# ─────────────────────────────────────────────

@mcp.tool()
async def analyze_hash(hash: str) -> str:
    """
    Identify the hash algorithm type (MD5, SHA-1, SHA-256, etc.) and query
    VirusTotal for reputation / threat intelligence on the hash.

    Args:
        hash: The hash string to analyze (MD5, SHA-1, SHA-256, SHA-512, etc.)
    """
    trimmed = hash.strip()

    hash_types = {
        32: "MD5",
        40: "SHA-1",
        56: "SHA-224",
        64: "SHA-256",
        96: "SHA-384",
        128: "SHA-512",
    }

    is_hex = bool(re.fullmatch(r"[0-9a-fA-F]+", trimmed))
    detected_type = (
        hash_types.get(len(trimmed), f"Unknown ({len(trimmed)} hex chars)")
        if is_hex
        else "Not a valid hex hash"
    )

    report = "## Hash Analysis Report\n\n"
    report += f"**Hash:** `{trimmed}`\n"
    report += f"**Detected Type:** {detected_type}\n"
    report += f"**Length:** {len(trimmed)} characters\n\n"

    if not is_hex:
        return report + "⚠️ Input does not appear to be a valid hexadecimal hash."

    if not VT_API_KEY:
        report += "> ℹ️ VirusTotal API key not configured — skipping reputation check.\n"
        return report

    try:
        res = await http_get(
            f"https://www.virustotal.com/api/v3/files/{trimmed}",
            headers={"x-apikey": VT_API_KEY},
        )

        if res.status_code == 404:
            report += "### VirusTotal\n\n✅ Hash **not found** in VirusTotal database — no known threat associations.\n"
        elif res.status_code == 200:
            data = res.json()
            attrs = data.get("data", {}).get("attributes", {})
            stats = attrs.get("last_analysis_stats", {})
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            harmless = stats.get("harmless", 0)
            undetected = stats.get("undetected", 0)
            total = malicious + suspicious + harmless + undetected
            name = attrs.get("meaningful_name", "N/A")
            file_type = attrs.get("type_description", "N/A")
            size = attrs.get("size", "N/A")
            vt_link = f"https://www.virustotal.com/gui/file/{trimmed}"

            threat_level = (
                "🔴 HIGH THREAT" if malicious > 10
                else "🟠 SUSPICIOUS" if malicious > 0
                else "🟢 CLEAN"
            )

            report += "### VirusTotal Reputation\n\n"
            report += f"**Threat Level:** {threat_level}\n"
            report += f"**Detections:** {malicious} malicious / {suspicious} suspicious out of {total} engines\n"
            report += f"**File Name:** {name}\n"
            report += f"**File Type:** {file_type}\n"
            if isinstance(size, int):
                report += f"**File Size:** {size / 1024:.1f} KB\n"
            else:
                report += f"**File Size:** {size}\n"
            report += f"**Harmless:** {harmless} | **Undetected:** {undetected}\n"
            report += f"**VT Link:** {vt_link}\n"
        else:
            report += f"### VirusTotal\n\n⚠️ API returned status {res.status_code}.\n"
    except Exception as e:
        report += f"### VirusTotal\n\n⚠️ Request failed: {e}\n"

    return report


# ─────────────────────────────────────────────
# TOOL 2 — check_cve
# ─────────────────────────────────────────────

@mcp.tool()
async def check_cve(cve_id: str) -> str:
    """
    Look up a CVE ID from the NIST National Vulnerability Database (NVD).
    Returns severity, CVSS score, description, attack vector, and references.

    Args:
        cve_id: CVE identifier, e.g. CVE-2021-44228 (Log4Shell)
    """
    cid = cve_id.strip().upper()

    if not re.fullmatch(r"CVE-\d{4}-\d{4,}", cid):
        return f"❌ Invalid CVE format: \"{cid}\". Expected format: CVE-YYYY-NNNNN"

    try:
        res = await http_get(f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cid}")

        if not res.is_success:
            return f"NVD API returned HTTP {res.status_code} for {cid}"

        data = res.json()
        vulns = data.get("vulnerabilities", [])

        if not vulns:
            return f"## {cid}\n\nℹ️ Not found in the NVD database."

        vuln = vulns[0].get("cve", {})
        descriptions = vuln.get("descriptions", [])
        description = next(
            (d["value"] for d in descriptions if d.get("lang") == "en"),
            "No description available.",
        )

        metrics = vuln.get("metrics", {})
        cvss_data = None
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            entries = metrics.get(key, [])
            if entries:
                cvss_data = entries[0]
                break

        if cvss_data:
            cd = cvss_data.get("cvssData", {})
            score = cd.get("baseScore", "N/A")
            severity = cd.get("baseSeverity", cvss_data.get("baseSeverity", "N/A"))
            vector = cd.get("vectorString", "N/A")
            attack_vector = cd.get("attackVector", "N/A")
            privileges = cd.get("privilegesRequired", "N/A")
            user_interaction = cd.get("userInteraction", "N/A")
        else:
            score = severity = vector = attack_vector = privileges = user_interaction = "N/A"

        published = (vuln.get("published") or "N/A")[:10]
        modified = (vuln.get("lastModified") or "N/A")[:10]

        references = vuln.get("references", [])
        ref_links = "\n".join(f"- {r['url']}" for r in references[:5])

        sev_emoji = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}.get(
            str(severity).upper(), "⚪"
        )

        report = f"## {cid}\n\n"
        report += f"**Severity:** {sev_emoji} {severity}\n"
        report += f"**CVSS Score:** {score} / 10\n"
        report += f"**Vector String:** `{vector}`\n"
        report += f"**Attack Vector:** {attack_vector}\n"
        report += f"**Privileges Required:** {privileges}\n"
        report += f"**User Interaction:** {user_interaction}\n"
        report += f"**Published:** {published} | **Last Modified:** {modified}\n\n"
        report += f"### Description\n\n{description}\n\n"
        if ref_links:
            report += f"### References (top 5)\n\n{ref_links}\n\n"
        report += f"### NVD Link\nhttps://nvd.nist.gov/vuln/detail/{cid}\n"

        return report

    except Exception as e:
        return f"Failed to query NVD: {e}"


# ─────────────────────────────────────────────
# TOOL 3 — scan_headers
# ─────────────────────────────────────────────

@mcp.tool()
async def scan_headers(url: str) -> str:
    """
    Fetch HTTP response headers from a URL and audit them for security best
    practices: CSP, HSTS, X-Frame-Options, X-Content-Type-Options,
    Referrer-Policy, Permissions-Policy, and server fingerprinting.

    Args:
        url: The full URL to audit, e.g. https://example.com
    """
    try:
        res = await http_get(url)
        headers = {k.lower(): v for k, v in res.headers.items()}

        checks = [
            {
                "header": "Strict-Transport-Security",
                "key": "strict-transport-security",
                "recommendation": "Set: max-age=31536000; includeSubDomains; preload",
                "severity": "HIGH",
            },
            {
                "header": "Content-Security-Policy",
                "key": "content-security-policy",
                "recommendation": "Define a restrictive CSP to prevent XSS and data injection attacks.",
                "severity": "HIGH",
            },
            {
                "header": "X-Frame-Options",
                "key": "x-frame-options",
                "recommendation": "Set to DENY or SAMEORIGIN to prevent clickjacking.",
                "severity": "MEDIUM",
            },
            {
                "header": "X-Content-Type-Options",
                "key": "x-content-type-options",
                "recommendation": "Set to: nosniff",
                "severity": "MEDIUM",
            },
            {
                "header": "Referrer-Policy",
                "key": "referrer-policy",
                "recommendation": "Set to: strict-origin-when-cross-origin or no-referrer",
                "severity": "LOW",
            },
            {
                "header": "Permissions-Policy",
                "key": "permissions-policy",
                "recommendation": "Restrict browser features (camera, microphone, geolocation).",
                "severity": "LOW",
            },
            {
                "header": "X-XSS-Protection",
                "key": "x-xss-protection",
                "recommendation": "Legacy header — set to 0 (disabled); CSP supersedes it.",
                "severity": "INFO",
            },
        ]

        present = [c for c in checks if c["key"] in headers]
        missing = [c for c in checks if c["key"] not in headers]

        high_missing = sum(1 for c in missing if c["severity"] == "HIGH")
        med_missing = sum(1 for c in missing if c["severity"] == "MEDIUM")

        grade = (
            "F" if high_missing >= 2
            else "D" if high_missing == 1
            else "C" if med_missing >= 2
            else "B" if med_missing == 1
            else "A"
        )

        report = "## HTTP Security Header Audit\n\n"
        report += f"**Target:** {url}\n"
        report += f"**Status:** HTTP {res.status_code}\n"
        report += f"**Security Grade:** {grade}\n\n"

        report += f"### ✅ Present Headers ({len(present)})\n\n"
        for c in present:
            val = headers[c["key"]]
            report += f"**{c['header']}**\n`{val}`\n\n"

        if missing:
            report += f"### ❌ Missing Headers ({len(missing)})\n\n"
            for c in missing:
                badge = {"HIGH": "🔴", "MEDIUM": "🟠", "LOW": "🟡", "INFO": "⚪"}.get(c["severity"], "⚪")
                report += f"{badge} **{c['header']}** [{c['severity']}]\n"
                report += f"> Recommendation: {c['recommendation']}\n\n"

        report += "### Server Fingerprinting\n\n"
        server_hdr = headers.get("server") or headers.get("x-powered-by")
        if server_hdr:
            report += f"⚠️ Server fingerprint exposed: `{server_hdr}` — consider removing this header.\n"
        else:
            report += "✅ No server/technology fingerprinting headers detected.\n"

        return report

    except Exception as e:
        return f"❌ Failed to fetch headers: {e}"


# ─────────────────────────────────────────────
# TOOL 4 — whois_lookup
# ─────────────────────────────────────────────

@mcp.tool()
async def whois_lookup(domain: str) -> str:
    """
    Perform WHOIS and passive DNS reconnaissance on a domain using RDAP
    (modern WHOIS standard), Cloudflare DNS-over-HTTPS, and IP geolocation.

    Args:
        domain: The domain name to investigate, e.g. example.com
    """
    cleaned = re.sub(r"^https?://", "", domain.strip().lower())
    cleaned = re.sub(r"/.*$", "", cleaned)

    report = f"## OSINT / WHOIS Report: {cleaned}\n\n"

    # RDAP lookup
    try:
        rdap_res = await http_get(f"https://rdap.org/domain/{cleaned}")

        if rdap_res.is_success:
            rdap = rdap_res.json()
            events = rdap.get("events", [])

            def get_event(action: str) -> str:
                return next(
                    (e["eventDate"][:10] for e in events if e.get("eventAction") == action),
                    "N/A",
                )

            name_servers = [ns["ldhName"] for ns in rdap.get("nameservers", [])]
            entities = rdap.get("entities", [])
            registrar = next((e for e in entities if "registrar" in e.get("roles", [])), None)
            registrar_name = "N/A"
            if registrar:
                vcard = registrar.get("vcardArray", [[], []])[1]
                fn = next((v[3] for v in vcard if v[0] == "fn"), "N/A")
                registrar_name = fn

            status_list = rdap.get("status", [])
            report += "### Registration Details\n\n"
            report += f"**Domain:** {rdap.get('ldhName', cleaned)}\n"
            report += f"**Registrar:** {registrar_name}\n"
            report += f"**Status:** {', '.join(status_list) or 'N/A'}\n"
            report += f"**Created:** {get_event('registration')}\n"
            report += f"**Updated:** {get_event('last changed')}\n"
            report += f"**Expires:** {get_event('expiration')}\n\n"
            ns_list = "\n".join(f"- {ns}" for ns in name_servers) or "N/A"
            report += f"**Name Servers:**\n{ns_list}\n\n"
        else:
            report += f"> ℹ️ RDAP returned HTTP {rdap_res.status_code} — domain may not exist.\n\n"
    except Exception as e:
        report += f"> ⚠️ RDAP lookup failed: {e}\n\n"

    # DNS over HTTPS
    try:
        dns_res = await http_get(
            f"https://cloudflare-dns.com/dns-query?name={cleaned}&type=A",
            headers={"Accept": "application/dns-json"},
        )

        if dns_res.is_success:
            dns = dns_res.json()
            a_records = [r["data"] for r in dns.get("Answer", []) if r.get("type") == 1]

            report += "### DNS Resolution\n\n"
            if a_records:
                report += f"**A Records (IPv4):** {', '.join(a_records)}\n\n"

                # IP Geolocation (first record)
                ip = a_records[0]
                try:
                    geo_res = await http_get(
                        f"http://ip-api.com/json/{ip}?fields=status,country,regionName,city,isp,org,as"
                    )
                    if geo_res.is_success:
                        geo = geo_res.json()
                        if geo.get("status") == "success":
                            report += f"### IP Intelligence: {ip}\n\n"
                            report += f"**Location:** {geo.get('city')}, {geo.get('regionName')}, {geo.get('country')}\n"
                            report += f"**ISP:** {geo.get('isp')}\n"
                            report += f"**Org:** {geo.get('org')}\n"
                            report += f"**ASN:** {geo.get('as')}\n\n"
                except Exception:
                    pass
            else:
                report += f"No A records found for {cleaned}.\n\n"
    except Exception as e:
        report += f"⚠️ DNS lookup failed: {e}\n"

    return report


# ─────────────────────────────────────────────
# TOOL 5 — decode_payload
# ─────────────────────────────────────────────

@mcp.tool()
async def decode_payload(
    payload: str,
    encoding: str = "auto",
) -> str:
    """
    Decode obfuscated or encoded payloads commonly found in malware analysis,
    CTF challenges, and phishing emails.
    Supports: base64, url, hex, rot13, auto (tries all).

    Args:
        payload: The encoded string to decode
        encoding: One of: base64 | url | hex | rot13 | auto (default: auto)
    """
    if encoding not in ("base64", "url", "hex", "rot13", "auto"):
        return f"❌ Unknown encoding '{encoding}'. Use: base64, url, hex, rot13, or auto."

    trimmed = payload.strip()
    report = "## Payload Decoder\n\n"
    report += f"**Input:** `{trimmed[:100]}{'…' if len(trimmed) > 100 else ''}`\n"
    report += f"**Mode:** {encoding}\n\n"

    def try_base64(s: str) -> str | None:
        try:
            decoded = base64.b64decode(s + "==").decode("utf-8")
            if re.search(r"[\x00-\x08\x0e-\x1f\x7f]", decoded):
                return None
            return decoded
        except Exception:
            return None

    def try_hex(s: str) -> str | None:
        cleaned = re.sub(r"\s+|0x", "", s)
        if not re.fullmatch(r"[0-9a-fA-F]+", cleaned) or len(cleaned) % 2 != 0:
            return None
        try:
            return bytes.fromhex(cleaned).decode("utf-8")
        except Exception:
            return None

    def try_url(s: str) -> str | None:
        try:
            decoded = unquote(s)
            return decoded if decoded != s else None
        except Exception:
            return None

    def rot13(s: str) -> str:
        result = []
        for c in s:
            if "a" <= c <= "z":
                result.append(chr((ord(c) - ord("a") + 13) % 26 + ord("a")))
            elif "A" <= c <= "Z":
                result.append(chr((ord(c) - ord("A") + 13) % 26 + ord("A")))
            else:
                result.append(c)
        return "".join(result)

    if encoding in ("base64", "auto"):
        result = try_base64(trimmed)
        if result:
            report += f"### Base64 Decoded\n\n```\n{result}\n```\n\n"
        elif encoding == "base64":
            report += "❌ Invalid Base64 input.\n"
            return report

    if encoding in ("hex", "auto"):
        result = try_hex(trimmed)
        if result:
            report += f"### Hex Decoded\n\n```\n{result}\n```\n\n"
        elif encoding == "hex":
            report += "❌ Invalid hex input.\n"
            return report

    if encoding in ("url", "auto"):
        result = try_url(trimmed)
        if result:
            report += f"### URL Decoded\n\n```\n{result}\n```\n\n"
        elif encoding == "url":
            report += "⚠️ Input contains no URL-encoded characters.\n"
            return report

    if encoding in ("rot13", "auto"):
        result = rot13(trimmed)
        report += f"### ROT13 Decoded\n\n```\n{result}\n```\n\n"

    if encoding == "auto":
        report += "> ℹ️ Attempted all encodings in auto mode. Results shown above."

    return report


# ─────────────────────────────────────────────
# TOOL 6 — password_strength
# ─────────────────────────────────────────────

@mcp.tool()
async def password_strength(password: str) -> str:
    """
    Analyze password strength against NIST SP 800-63b guidelines.
    Checks length, entropy, character diversity, and common weak patterns.
    The password is analyzed locally — it is NEVER transmitted over the network.

    Args:
        password: The password to analyze (processed locally, never stored or transmitted)
    """
    length = len(password)

    has_upper = bool(re.search(r"[A-Z]", password))
    has_lower = bool(re.search(r"[a-z]", password))
    has_digit = bool(re.search(r"[0-9]", password))
    has_symbol = bool(re.search(r"[^A-Za-z0-9]", password))
    class_count = sum([has_upper, has_lower, has_digit, has_symbol])

    pool_size = (
        (26 if has_upper else 0)
        + (26 if has_lower else 0)
        + (10 if has_digit else 0)
        + (32 if has_symbol else 0)
    )
    entropy = math.log2(pool_size) * length if pool_size > 0 else 0

    weak_patterns = [
        (r"^(.)\1+$", "All same character"),
        (r"^(012|123|234|345|456|567|678|789|890|987|876|765|654|543|432|321|210)", "Sequential numbers"),
        (r"^(abc|bcd|cde|def|efg|fgh|ghi|hij|ijk|jkl|klm|lmn|mno|nop|opq|pqr|qrs|rst|stu|tuv|uvw|vwx|wxy|xyz)", "Sequential letters"),
        (r"password|passwd|p@ssw0rd|pa55word|letmein|welcome|admin|login|qwerty|iloveyou", "Common password keyword"),
    ]
    triggered = [label for pattern, label in weak_patterns if re.search(pattern, password, re.IGNORECASE)]

    score = 0
    if length >= 8: score += 1
    if length >= 12: score += 1
    if length >= 16: score += 1
    if class_count >= 3: score += 1
    if entropy >= 50: score += 1
    if not triggered: score += 1

    strength_label = (
        "💪 STRONG" if score >= 5
        else "⚠️ MODERATE" if score >= 3
        else "🔴 WEAK"
    )

    report = "## Password Strength Analysis\n\n"
    report += "> 🔒 Password is analyzed **locally**. It is never sent over the network.\n\n"
    report += f"**Length:** {length} characters\n"
    report += f"**Entropy (estimate):** {entropy:.1f} bits\n"
    report += f"**Character Classes Used:** {class_count}/4\n"
    report += f"  - Uppercase: {'✅' if has_upper else '❌'}\n"
    report += f"  - Lowercase: {'✅' if has_lower else '❌'}\n"
    report += f"  - Digits: {'✅' if has_digit else '❌'}\n"
    report += f"  - Symbols: {'✅' if has_symbol else '❌'}\n\n"
    report += f"**Overall Strength:** {strength_label} ({score}/6)\n\n"

    if triggered:
        report += "### ⚠️ Weak Patterns Detected\n\n"
        for p in triggered:
            report += f"- {p}\n"
        report += "\n"

    report += "### NIST SP 800-63b Recommendations\n\n"
    if length < 8:
        report += "❌ Minimum length is **8 characters** (NIST requirement).\n"
    if length < 12:
        report += "💡 Prefer **12+ characters** for general use.\n"
    if length < 16:
        report += "💡 Use **16+ characters** for high-value accounts.\n"
    if class_count < 3:
        report += "💡 Use a mix of uppercase, lowercase, digits, and symbols.\n"
    if entropy < 36:
        report += "❌ Entropy is critically low — easily brute-forced.\n"
    if entropy >= 50:
        report += "✅ Entropy is sufficient for strong protection.\n"

    report += "\n### Key NIST Principles\n\n"
    report += "- ✅ Prioritize **length over complexity**.\n"
    report += "- ✅ Use a **passphrase** (e.g. 4 random words) for memorability + strength.\n"
    report += "- ✅ Enable **MFA** — password strength alone is insufficient.\n"
    report += "- ✅ Check passwords against **breach databases** (e.g. HaveIBeenPwned).\n"
    report += "- ❌ Do NOT enforce mandatory periodic password changes (per NIST 800-63b).\n"

    return report


# ─────────────────────────────────────────────
# TOOL 7 — generate_threat_report
# ─────────────────────────────────────────────

@mcp.tool()
async def generate_threat_report(
    target: str,
    attack_type: str = "unknown",
    severity: str = "medium",
    domain: str = "",
    ip_addresses: list[str] | None = None,
    file_hashes: list[str] | None = None,
    cve_ids: list[str] | None = None,
    observations: str = "",
    threat_actor: str = "",
) -> str:
    """
    Generate a structured threat intelligence report from collected findings.
    Follows NIST Cybersecurity Framework and MITRE ATT&CK mappings.

    Args:
        target: Primary target being investigated (domain, IP, org name, or system)
        attack_type: Category: phishing | ransomware | apt | web-attack | insider-threat | supply-chain | unknown
        severity: Analyst-assessed severity: critical | high | medium | low
        domain: Domain associated with the threat (optional)
        ip_addresses: List of IP addresses observed (optional)
        file_hashes: List of file hashes as IOCs (optional)
        cve_ids: List of CVE IDs exploited (optional)
        observations: Free-form analyst observations / TTPs (optional)
        threat_actor: Known/suspected threat actor name, e.g. APT29 (optional)
    """
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    sev_emoji = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢"}.get(severity, "⚪")

    mitre_tactics = {
        "phishing": ["Initial Access (T1566)", "Credential Access (T1539)", "Collection (T1114)"],
        "ransomware": ["Execution (T1059)", "Impact (T1486 — Data Encrypted)", "Discovery (T1083)"],
        "apt": ["Persistence (T1053)", "Lateral Movement (T1021)", "Exfiltration (T1048)"],
        "web-attack": ["Initial Access (T1190)", "Execution (T1059.007)", "Defense Evasion (T1140)"],
        "insider-threat": ["Collection (T1213)", "Exfiltration (T1567)", "Impact (T1485)"],
        "supply-chain": ["Initial Access (T1195)", "Persistence (T1554)", "Execution (T1072)"],
        "unknown": ["Initial Access", "Execution", "Persistence"],
    }
    tactics = mitre_tactics.get(attack_type, mitre_tactics["unknown"])

    actions_map = {
        "phishing": [
            "Block sender domain and IP at email gateway.",
            "Reset credentials for affected users immediately.",
            "Enable MFA on all email accounts.",
            "Conduct user awareness training.",
        ],
        "ransomware": [
            "Isolate affected systems from network immediately.",
            "Do NOT pay the ransom — contact law enforcement (FBI IC3).",
            "Restore from clean offline backups.",
            "Patch vulnerable systems and update EDR signatures.",
        ],
        "apt": [
            "Initiate full incident response procedure.",
            "Preserve forensic evidence before remediation.",
            "Audit privileged accounts and review AD changes.",
            "Engage a threat hunting team.",
        ],
        "web-attack": [
            "Apply WAF rules to block the attack vector.",
            "Patch the exploited vulnerability immediately.",
            "Review web server access logs for lateral movement.",
            "Rotate any exposed API keys or credentials.",
        ],
        "insider-threat": [
            "Suspend the user account and revoke access tokens.",
            "Preserve audit logs for legal proceedings.",
            "Notify HR and legal teams.",
            "Review DLP alerts for data exfiltration.",
        ],
        "supply-chain": [
            "Audit all third-party software and dependencies.",
            "Verify integrity hashes of software packages.",
            "Apply vendor patches immediately.",
            "Review network traffic for unexpected outbound connections.",
        ],
        "unknown": [
            "Isolate affected systems.",
            "Preserve logs and forensic artifacts.",
            "Escalate to security team for full investigation.",
        ],
    }
    action_list = actions_map.get(attack_type, actions_map["unknown"])

    report = "# Threat Intelligence Report\n\n"
    report += "---\n\n"
    report += "| Field | Value |\n|---|---|\n"
    report += f"| **Report Date** | {now} |\n"
    report += f"| **Target** | {target} |\n"
    report += f"| **Attack Type** | {attack_type.upper()} |\n"
    report += f"| **Severity** | {sev_emoji} {severity.upper()} |\n"
    if threat_actor:
        report += f"| **Threat Actor** | {threat_actor} |\n"
    report += "\n---\n\n"

    report += "## Executive Summary\n\n"
    report += f"This report documents a **{severity.upper()}** severity {attack_type} incident targeting **{target}**. "
    if threat_actor:
        report += f"The activity is attributed to or consistent with **{threat_actor}**. "
    report += "Immediate containment and remediation actions are recommended per the guidelines below.\n\n"

    report += "## Indicators of Compromise (IOCs)\n\n"
    if domain:
        report += f"**Domain:** `{domain}`\n"
    if ip_addresses:
        report += "**IP Addresses:**\n" + "\n".join(f"- `{ip}`" for ip in ip_addresses) + "\n"
    if file_hashes:
        report += "**File Hashes:**\n" + "\n".join(f"- `{h}`" for h in file_hashes) + "\n"
    if cve_ids:
        report += "**Exploited CVEs:**\n" + "\n".join(
            f"- [{c}](https://nvd.nist.gov/vuln/detail/{c})" for c in cve_ids
        ) + "\n"
    report += "\n"

    if observations:
        report += f"## Analyst Observations\n\n{observations}\n\n"

    report += "## MITRE ATT&CK Mapping\n\n"
    report += f"Likely tactics/techniques for **{attack_type}** attacks:\n\n"
    for t in tactics:
        report += f"- {t}\n"
    report += "\n> Full mapping: https://attack.mitre.org\n\n"

    report += "## Recommended Actions\n\n"
    for i, action in enumerate(action_list, 1):
        report += f"{i}. {action}\n"
    report += "\n"

    report += "## References & Standards\n\n"
    report += "- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)\n"
    report += "- [MITRE ATT&CK Framework](https://attack.mitre.org)\n"
    report += "- [CISA Advisories](https://www.cisa.gov/uscert/ncas/alerts)\n"
    if cve_ids:
        report += "- [NVD Vulnerability Database](https://nvd.nist.gov)\n"

    report += "\n---\n*Report generated by CyberSec MCP Server v1.0.0*\n"

    return report


# ─────────────────────────────────────────────
# Entrypoint
# ─────────────────────────────────────────────

if __name__ == "__main__":
    mcp.run(transport="stdio")
