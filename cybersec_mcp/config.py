"""Central configuration. Everything tunable lives here, sourced from env vars.

Nothing in this module reads a file or makes a network call, so it is safe to
import from tests.
"""

from __future__ import annotations

import os
from pathlib import Path

VERSION = "2.0.0"
SERVER_NAME = "cybersec-mcp"


def _int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, "") or default)
    except ValueError:
        return default


def _bool(name: str, default: bool = False) -> bool:
    raw = os.environ.get(name, "").strip().lower()
    if not raw:
        return default
    return raw in {"1", "true", "yes", "on"}


# ── Credentials ───────────────────────────────────────────────────────────
# Read once at import. Never logged, never echoed back into tool output.
VT_API_KEY: str = os.environ.get("VIRUSTOTAL_API_KEY", "").strip()
NVD_API_KEY: str = os.environ.get("NVD_API_KEY", "").strip()

# All values that must be scrubbed from any error string before it reaches
# the model's context.
SECRETS: tuple[str, ...] = tuple(v for v in (VT_API_KEY, NVD_API_KEY) if len(v) >= 8)

# ── Network policy ────────────────────────────────────────────────────────
HTTP_TIMEOUT_S: float = float(_int("CYBERSEC_MCP_TIMEOUT", 12))
MAX_REDIRECTS: int = _int("CYBERSEC_MCP_MAX_REDIRECTS", 3)
MAX_RESPONSE_BYTES: int = _int("CYBERSEC_MCP_MAX_RESPONSE_BYTES", 512_000)

# Ports the header scanner is permitted to reach. Blocks the classic
# SSRF pivot into internal services (redis 6379, memcached 11211, ...).
ALLOWED_PORTS: frozenset[int] = frozenset(
    int(p) for p in os.environ.get(
        "CYBERSEC_MCP_ALLOWED_PORTS", "80,443,8080,8443"
    ).split(",") if p.strip().isdigit()
)

# Set CYBERSEC_MCP_ALLOW_PRIVATE_TARGETS=1 ONLY on an isolated lab box where
# you deliberately want to scan RFC1918 space. Never set it on a host that
# has cloud instance metadata (IMDS) or any credential-bearing endpoint.
ALLOW_PRIVATE_TARGETS: bool = _bool("CYBERSEC_MCP_ALLOW_PRIVATE_TARGETS", False)

# ── Caching & throttling ──────────────────────────────────────────────────
CACHE_TTL_S: int = _int("CYBERSEC_MCP_CACHE_TTL", 900)
CACHE_MAX_ENTRIES: int = _int("CYBERSEC_MCP_CACHE_MAX", 256)

# Requests per minute per upstream host. Defaults sit under the documented
# free-tier limits: VirusTotal 4/min, NVD 5 per 30s without an API key.
RATE_LIMITS: dict[str, int] = {
    "www.virustotal.com": _int("CYBERSEC_MCP_RL_VT", 4),
    "services.nvd.nist.gov": _int("CYBERSEC_MCP_RL_NVD", 50 if NVD_API_KEY else 8),
    "api.pwnedpasswords.com": 30,
    "*": 30,
}

# ── Output limits (context-window protection) ─────────────────────────────
MAX_UNTRUSTED_CHARS: int = _int("CYBERSEC_MCP_MAX_UNTRUSTED_CHARS", 1500)
MAX_TOOL_OUTPUT_CHARS: int = _int("CYBERSEC_MCP_MAX_OUTPUT_CHARS", 12_000)

# ── Audit log ─────────────────────────────────────────────────────────────
AUDIT_ENABLED: bool = _bool("CYBERSEC_MCP_AUDIT", True)
AUDIT_PATH: Path = Path(
    os.environ.get("CYBERSEC_MCP_AUDIT_PATH", "")
    or (Path.home() / ".cybersec-mcp" / "audit.jsonl")
)

USER_AGENT = f"cybersec-mcp/{VERSION} (+https://github.com/fa1829/cybersec-mcp)"
