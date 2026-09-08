"""HTTP response-header audit.

This is the tool that made v1 an SSRF proxy: it fetched any URL the model
supplied, with redirects followed automatically. Every request now goes through
``httpclient.fetch``, which validates the target and re-validates every hop.
"""

from __future__ import annotations

from ..httpclient import describe_error, fetch, redirect_note
from ..safety import inline

CHECKS = [
    {
        "header": "Strict-Transport-Security",
        "key": "strict-transport-security",
        "severity": "HIGH",
        "why": "Without HSTS a first visit over http can be intercepted and downgraded.",
        "fix": "Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
    },
    {
        "header": "Content-Security-Policy",
        "key": "content-security-policy",
        "severity": "HIGH",
        "why": "CSP is the main structural defence against XSS and injected third-party scripts.",
        "fix": "Start with: default-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'self'",
    },
    {
        "header": "X-Frame-Options",
        "key": "x-frame-options",
        "severity": "MEDIUM",
        "why": "Prevents clickjacking. Superseded by CSP frame-ancestors, still needed for old browsers.",
        "fix": "X-Frame-Options: DENY",
    },
    {
        "header": "X-Content-Type-Options",
        "key": "x-content-type-options",
        "severity": "MEDIUM",
        "why": "Stops MIME sniffing turning an uploaded file into executable script.",
        "fix": "X-Content-Type-Options: nosniff",
    },
    {
        "header": "Referrer-Policy",
        "key": "referrer-policy",
        "severity": "LOW",
        "why": "Limits leaking internal URLs and tokens in the Referer header.",
        "fix": "Referrer-Policy: strict-origin-when-cross-origin",
    },
    {
        "header": "Permissions-Policy",
        "key": "permissions-policy",
        "severity": "LOW",
        "why": "Denies camera, microphone and geolocation to the page and its frames.",
        "fix": "Permissions-Policy: camera=(), microphone=(), geolocation=()",
    },
    {
        "header": "Cross-Origin-Opener-Policy",
        "key": "cross-origin-opener-policy",
        "severity": "LOW",
        "why": "Isolates the browsing context; a prerequisite for cross-origin isolation.",
        "fix": "Cross-Origin-Opener-Policy: same-origin",
    },
]

ICON = {"HIGH": "🔴", "MEDIUM": "🟠", "LOW": "🟡"}

# Headers that tell an attacker what to attack.
FINGERPRINT_KEYS = ("server", "x-powered-by", "x-aspnet-version", "x-generator", "x-drupal-cache")


def _grade(missing: list[dict]) -> str:
    high = sum(1 for c in missing if c["severity"] == "HIGH")
    medium = sum(1 for c in missing if c["severity"] == "MEDIUM")
    low = sum(1 for c in missing if c["severity"] == "LOW")
    if high >= 2:
        return "F"
    if high == 1:
        return "D"
    if medium >= 2:
        return "C"
    if medium == 1 or low >= 3:
        return "B"
    return "A"


async def scan_headers(url: str) -> str:
    """Audit a website's HTTP response headers against current hardening guidance.

    Reports which security headers are present, which are missing and why each
    matters, an overall grade, any technology fingerprinting, and cookie flags.
    Only public http/https targets on ports 80/443/8080/8443 are permitted;
    private, loopback and cloud-metadata addresses are refused.

    Args:
        url: Full URL to audit, e.g. https://example.com
    """
    try:
        response, hops = await fetch(url)
    except Exception as exc:  # noqa: BLE001
        return f"## HTTP security header audit\n\n**Target:** `{url[:200]}`\n\n" + describe_error(exc) + "\n"

    headers = {k.lower(): v for k, v in response.headers.items()}
    present = [c for c in CHECKS if c["key"] in headers]
    missing = [c for c in CHECKS if c["key"] not in headers]
    grade = _grade(missing)

    out = "## HTTP security header audit\n\n"
    out += "| Field | Value |\n|---|---|\n"
    out += f"| Target | `{url[:200]}` |\n"
    out += f"| Resolved to | {', '.join(hops[0].addresses) or 'n/a'} |\n"
    out += f"| Status | HTTP {response.status_code} |\n"
    out += f"| Grade | **{grade}** ({len(present)}/{len(CHECKS)} headers present) |\n\n"
    out += redirect_note(hops)

    if present:
        out += f"### Present ({len(present)})\n\n"
        for check in present:
            out += f"- **{check['header']}** — `{inline(headers[check['key']], 200)}`\n"
        out += "\n"

    if missing:
        out += f"### Missing ({len(missing)})\n\n"
        for check in sorted(missing, key=lambda c: ("HIGH", "MEDIUM", "LOW").index(c["severity"])):
            out += f"{ICON[check['severity']]} **{check['header']}** — {check['severity']}\n"
            out += f"  - {check['why']}\n"
            out += f"  - Fix: `{check['fix']}`\n\n"

    # HSTS present but weak is a common false pass.
    hsts = headers.get("strict-transport-security", "")
    if hsts:
        try:
            max_age = int(next(p.split("=")[1] for p in hsts.split(";") if "max-age" in p))
            if max_age < 31_536_000:
                out += (
                    f"> ⚠️ HSTS max-age is {max_age:,}s, under the 1-year "
                    "(31,536,000s) minimum required for preload eligibility.\n\n"
                )
        except (StopIteration, ValueError, IndexError):
            pass

    out += "### Fingerprinting\n\n"
    exposed = [(k, headers[k]) for k in FINGERPRINT_KEYS if k in headers]
    if exposed:
        for key, value in exposed:
            out += f"- ⚠️ `{key}: {inline(value, 120)}` — reveals the stack and its version.\n"
        out += "\n"
    else:
        out += "- ✅ No obvious technology-fingerprinting headers.\n\n"

    cookies = response.headers.get_list("set-cookie") if hasattr(response.headers, "get_list") else []
    if cookies:
        out += "### Cookies\n\n"
        for raw in cookies[:6]:
            lowered = raw.lower()
            flags = [
                ("Secure", "secure" in lowered),
                ("HttpOnly", "httponly" in lowered),
                ("SameSite", "samesite" in lowered),
            ]
            name = raw.split("=", 1)[0][:60]
            marks = " ".join(f"{'✅' if ok else '❌'} {flag}" for flag, ok in flags)
            out += f"- `{inline(name, 60)}` — {marks}\n"
        out += "\n"

    out += (
        "> Grades reflect response headers only. They say nothing about "
        "authentication, authorisation or application logic — the places real "
        "breaches usually start.\n"
    )
    return out
