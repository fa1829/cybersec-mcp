"""Tool implementations. Each is a plain async function returning Markdown.

Keeping them free of MCP decorators means they can be unit-tested directly and
re-registered under a different transport without change.
"""

from .cve import check_cve
from .decode import decode_payload
from .hashes import analyze_hash
from .headers import scan_headers
from .osint import whois_lookup
from .passwords import password_strength
from .report import generate_threat_report
from .triage import triage_alert, triage_indicator

__all__ = [
    "analyze_hash",
    "check_cve",
    "decode_payload",
    "generate_threat_report",
    "password_strength",
    "scan_headers",
    "triage_alert",
    "triage_indicator",
    "whois_lookup",
]
