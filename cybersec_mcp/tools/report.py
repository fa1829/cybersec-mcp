"""Structured incident/threat report generator.

Honest framing: this is a **template filler**, not an analysis engine. It takes
findings an analyst (or the other tools here) already produced and lays them out
in a consistent shape — MITRE ATT&CK context, NIST SP 800-61 response phases,
and an explicit confidence statement. It does not decide anything. The value is
consistency and completeness, which is exactly what falls apart when incident
notes are written by hand at 2am.
"""

from __future__ import annotations

from datetime import datetime, timezone

from ..safety import defang, inline, sanitize

SEVERITY_ICON = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢", "info": "⚪"}

ATTACK_PROFILES: dict[str, dict[str, list[str]]] = {
    "phishing": {
        "techniques": [
            "T1566.002 — Phishing: Spearphishing Link",
            "T1204.001 — User Execution: Malicious Link",
            "T1539 — Steal Web Session Cookie",
            "T1556.006 — Modify Authentication Process: MFA",
        ],
        "contain": [
            "Block the sender domain, sending IP and any linked infrastructure at the mail gateway.",
            "Purge delivered copies from all mailboxes, not just the reported one.",
            "Revoke active sessions and refresh tokens for affected users — a password reset alone leaves stolen cookies valid.",
        ],
        "eradicate": [
            "Reset credentials and re-enrol MFA for anyone who submitted them.",
            "Hunt for inbox rules, mail-forwarding and OAuth app grants created after the click.",
        ],
        "recover": [
            "Restore mailbox rules and delegated permissions to a known-good state.",
            "Move affected users to phishing-resistant MFA (FIDO2/passkeys) — push-based MFA does not stop AiTM proxies.",
        ],
    },
    "ransomware": {
        "techniques": [
            "T1486 — Data Encrypted for Impact",
            "T1490 — Inhibit System Recovery",
            "T1567 — Exfiltration Over Web Service (double extortion)",
            "T1078 — Valid Accounts",
        ],
        "contain": [
            "Isolate at the network layer; do not power off — memory holds keys and evidence.",
            "Disable the compromised accounts and revoke their Kerberos tickets.",
            "Take backup infrastructure offline before the attacker reaches it.",
        ],
        "eradicate": [
            "Identify the initial access vector before rebuilding, or it will be reused.",
            "Rebuild from known-good images rather than cleaning in place.",
            "Rotate every credential that touched an affected host, including service accounts and Kerberos krbtgt.",
        ],
        "recover": [
            "Restore from offline, integrity-verified backups; test the restore path before committing.",
            "Assume data was exfiltrated before encryption and open the breach-notification clock accordingly.",
            "Paying does not guarantee decryption and may carry sanctions exposure — involve legal and law enforcement.",
        ],
    },
    "web-attack": {
        "techniques": [
            "T1190 — Exploit Public-Facing Application",
            "T1505.003 — Server Software Component: Web Shell",
            "T1059.004 — Command and Scripting Interpreter: Unix Shell",
        ],
        "contain": [
            "Deploy a targeted WAF rule for the observed vector as a stopgap, not as the fix.",
            "Take the affected endpoint out of the load-balancer pool.",
        ],
        "eradicate": [
            "Patch the underlying vulnerability; virtual patching alone leaves the flaw reachable by other paths.",
            "Diff the webroot against source control to find dropped web shells.",
            "Rotate every credential and API key readable from the compromised host.",
        ],
        "recover": [
            "Redeploy from CI rather than repairing the running host.",
            "Add a regression test reproducing the exploited input.",
        ],
    },
    "supply-chain": {
        "techniques": [
            "T1195.002 — Compromise Software Supply Chain",
            "T1554 — Compromise Host Software Binary",
            "T1072 — Software Deployment Tools",
        ],
        "contain": [
            "Pin or roll back the affected dependency version across every environment.",
            "Block egress from build agents to unexpected destinations.",
        ],
        "eradicate": [
            "Generate an SBOM and find every consumer of the compromised component.",
            "Rotate any secret a build agent could read — CI credentials are the usual prize.",
        ],
        "recover": [
            "Move to pinned, hash-verified dependencies with a committed lockfile.",
            "Require review for dependency updates the way you require it for code.",
        ],
    },
    "insider-threat": {
        "techniques": [
            "T1213 — Data from Information Repositories",
            "T1567.002 — Exfiltration to Cloud Storage",
            "T1078.004 — Valid Accounts: Cloud Accounts",
        ],
        "contain": [
            "Coordinate with HR and Legal **before** touching the account — premature action destroys the case.",
            "Preserve endpoint, mailbox and DLP evidence under legal hold.",
        ],
        "eradicate": [
            "Revoke access at every layer including SaaS, VPN, physical badge and personal-device enrolment.",
            "Review what the account accessed across its full tenure, not just the alert window.",
        ],
        "recover": [
            "Re-scope the permissions that made the access possible.",
            "Document the detection gap that delayed discovery.",
        ],
    },
    "apt": {
        "techniques": [
            "T1078 — Valid Accounts",
            "T1021.001 — Remote Services: RDP",
            "T1053.005 — Scheduled Task/Job",
            "T1048 — Exfiltration Over Alternative Protocol",
        ],
        "contain": [
            "Do not tip off the intruder with piecemeal remediation; plan a coordinated eviction.",
            "Stand up out-of-band communications — assume email and chat are read.",
        ],
        "eradicate": [
            "Map the full footprint before acting, then evict everything in one window.",
            "Rotate krbtgt twice and audit every persistence mechanism.",
        ],
        "recover": [
            "Rebuild identity infrastructure rather than cleaning it.",
            "Keep enhanced monitoring in place for months, not days.",
        ],
    },
    "unknown": {
        "techniques": ["Insufficient evidence to map techniques."],
        "contain": ["Isolate affected systems while preserving volatile memory."],
        "eradicate": ["Establish the initial access vector before remediating."],
        "recover": ["Restore only after the entry point is closed and verified."],
    },
}


async def generate_threat_report(
    target: str,
    attack_type: str = "unknown",
    severity: str = "medium",
    confidence: str = "medium",
    domain: str = "",
    ip_addresses: list[str] | None = None,
    file_hashes: list[str] | None = None,
    cve_ids: list[str] | None = None,
    observations: str = "",
    threat_actor: str = "",
) -> str:
    """Lay analyst findings out as a structured incident report.

    Produces an executive summary, defanged IOC table, MITRE ATT&CK context and
    containment/eradication/recovery actions structured on NIST SP 800-61. This
    formats findings you supply — it performs no analysis and makes no
    attribution of its own.

    Args:
        target: System, domain, org or asset under investigation.
        attack_type: phishing | ransomware | web-attack | supply-chain | insider-threat | apt | unknown
        severity: critical | high | medium | low | info — your assessed impact.
        confidence: high | medium | low — how well the evidence supports the assessment.
        domain: Associated domain, if any.
        ip_addresses: Observed IP addresses.
        file_hashes: Observed file hashes.
        cve_ids: CVEs believed to be involved.
        observations: Free-text analyst notes and TTPs.
        threat_actor: Suspected actor, only if you have evidence for it.
    """
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    key = attack_type.strip().lower()
    profile = ATTACK_PROFILES.get(key, ATTACK_PROFILES["unknown"])
    sev = severity.strip().lower()
    conf = confidence.strip().lower()

    out = f"# Incident report — {inline(target, 80)}\n\n"
    out += "| Field | Value |\n|---|---|\n"
    out += f"| Generated | {now} |\n"
    out += f"| Target | {inline(target, 120)} |\n"
    out += f"| Category | {inline(key, 40)} |\n"
    out += f"| Severity | {SEVERITY_ICON.get(sev, '⚪')} {sev.upper()} |\n"
    out += f"| Confidence | {conf.upper()} |\n"
    if threat_actor:
        out += f"| Suspected actor | {inline(threat_actor, 60)} |\n"
    out += "\n"

    if key not in ATTACK_PROFILES:
        out += f"> ⚠️ `{inline(key, 40)}` is not a recognised category; generic guidance is shown.\n\n"

    out += "## Executive summary\n\n"
    out += (
        f"A **{sev}** severity {key} incident affecting **{inline(target, 120)}** was assessed "
        f"at **{conf}** confidence. "
    )
    if threat_actor:
        out += (
            f"Activity is reported as consistent with **{inline(threat_actor, 60)}**. "
            "Attribution stated here is analyst-supplied and should carry its own evidence trail. "
        )
    out += "Containment actions below are ordered by NIST SP 800-61 phase.\n\n"

    out += "## Indicators of compromise\n\n"
    rows = []
    if domain:
        rows.append(("Domain", defang(inline(domain, 120))))
    for ip in (ip_addresses or [])[:20]:
        rows.append(("IPv4/IPv6", defang(inline(ip, 60))))
    for h in (file_hashes or [])[:20]:
        rows.append(("File hash", inline(h, 140)))
    for c in (cve_ids or [])[:20]:
        rows.append(("CVE", inline(c, 30)))
    if rows:
        out += "| Type | Value (defanged) |\n|---|---|\n"
        out += "".join(f"| {t} | `{v}` |\n" for t, v in rows) + "\n"
    else:
        out += "None recorded. A report with no IOCs cannot support detection engineering — collect them.\n\n"

    if observations:
        out += "## Analyst observations\n"
        out += sanitize(observations, limit=3000).block("analyst-notes")
        out += "\n"

    out += "## MITRE ATT&CK context\n\n"
    out += "".join(f"- {t}\n" for t in profile["techniques"])
    out += (
        f"\n> These are the techniques *typical* of {key} incidents, not techniques observed "
        "in this one. Confirm each against your own evidence before it reaches a report "
        "anyone acts on. Full matrix: https://attack.mitre.org\n\n"
    )

    for phase, heading in (("contain", "Containment"), ("eradicate", "Eradication"), ("recover", "Recovery")):
        out += f"## {heading}\n\n"
        out += "".join(f"{i}. {a}\n" for i, a in enumerate(profile[phase], 1)) + "\n"

    out += "## References\n\n"
    out += "- NIST SP 800-61r3 — Incident Response Recommendations: https://csrc.nist.gov/pubs/sp/800/61/r3/final\n"
    out += "- MITRE ATT&CK: https://attack.mitre.org\n"
    out += "- CISA advisories: https://www.cisa.gov/news-events/cybersecurity-advisories\n"
    if cve_ids:
        out += "- CISA KEV catalog: https://www.cisa.gov/known-exploited-vulnerabilities-catalog\n"
    out += "\n---\n*Template generated by cybersec-mcp. Content is analyst-supplied; this tool performs no analysis.*\n"
    return out
