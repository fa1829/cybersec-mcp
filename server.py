#!/usr/bin/env python3
"""cybersec-mcp — MCP server entrypoint.

Registers the tool functions, wraps each in the audit decorator, and runs over
stdio. Run `python server.py --manifest` to print the tool-manifest digest
without starting the server; `--verify-audit` to check the audit chain.
"""

from __future__ import annotations

import functools
import inspect
import sys
import time
from typing import Any, Callable

from cybersec_mcp import audit, config
from cybersec_mcp.integrity import build_manifest, render_manifest
from cybersec_mcp.safety import cap, redact
from cybersec_mcp.tools import (
    analyze_hash,
    check_cve,
    decode_payload,
    generate_threat_report,
    password_strength,
    scan_headers,
    triage_alert,
    triage_indicator,
    whois_lookup,
)

# ── SDK compatibility ─────────────────────────────────────────────────────
# mcp 2.x renamed FastMCP to MCPServer. The decorator and run() signatures we
# use are unchanged, so one import shim covers both generations.
try:  # mcp >= 2.0
    from mcp.server.mcpserver import MCPServer as _ServerClass
    _SDK = "mcp>=2"
except ImportError:  # mcp 1.x
    from mcp.server.fastmcp import FastMCP as _ServerClass  # type: ignore[assignment]
    _SDK = "mcp<2"

mcp = _ServerClass(config.SERVER_NAME)

TOOLS: list[Callable[..., Any]] = [
    triage_indicator,
    triage_alert,
    analyze_hash,
    check_cve,
    scan_headers,
    whois_lookup,
    decode_payload,
    password_strength,
    generate_threat_report,
]


def audited(fn: Callable[..., Any]) -> Callable[..., Any]:
    """Log every invocation to the hash-chained audit log.

    functools.wraps keeps __doc__ and __wrapped__, so the MCP SDK still derives
    the tool's schema and description from the original function.
    """

    @functools.wraps(fn)
    async def wrapper(*args: Any, **kwargs: Any) -> str:
        bound = inspect.signature(fn).bind(*args, **kwargs)
        bound.apply_defaults()
        started = time.perf_counter()
        try:
            result = cap(await fn(*args, **kwargs))
            outcome = "ok"
            detail = ""
        except Exception as exc:  # noqa: BLE001 — never leak a traceback to the model
            result = redact(f"⚠️ {fn.__name__} failed: {type(exc).__name__}: {exc}")
            outcome = "error"
            detail = f"{type(exc).__name__}: {exc}"
        elapsed = int((time.perf_counter() - started) * 1000)
        # These two are the events worth grepping the audit log for.
        flags: list[str] = []
        if "Possible prompt injection" in result:
            flags.append("possible-injection")
        if "Blocked by network policy" in result:
            flags.append("ssrf-blocked")
        audit.record(
            fn.__name__,
            dict(bound.arguments),
            outcome=outcome,
            duration_ms=elapsed,
            flags=flags,
            detail=redact(detail),
        )
        return result

    return wrapper


for tool in TOOLS:
    mcp.tool()(audited(tool))


@mcp.tool()
async def tool_manifest() -> str:
    """Return this server's tool-manifest digest so a client can pin it.

    In MCP a tool description is an instruction the model acts on, so a changed
    description silently changes agent behaviour. Pin this digest and any change
    becomes a visible diff.
    """
    return render_manifest(build_manifest(TOOLS), config.VERSION)


@mcp.tool()
async def verify_audit_log() -> str:
    """Verify the integrity of this server's hash-chained audit log."""
    intact, summary = audit.verify_chain()
    icon = "✅" if intact else "🔴"
    return (
        f"## Audit log verification\n\n{icon} {summary}\n\n"
        f"**Path:** `{config.AUDIT_PATH}`\n\n"
        "> Tamper-evident, not tamper-proof: anyone who can write this file can "
        "recompute the chain. Ship it to append-only storage for stronger guarantees.\n"
    )


def _startup_banner() -> None:
    manifest = build_manifest(TOOLS)
    print(
        f"[{config.SERVER_NAME}] v{config.VERSION} | SDK {_SDK} | "
        f"{manifest['tool_count'] + 2} tools | manifest {manifest['digest'][:16]}… | "
        f"VT key: {'set' if config.VT_API_KEY else 'absent'} | "
        f"NVD key: {'set' if config.NVD_API_KEY else 'absent'} | "
        f"private targets: {'ALLOWED' if config.ALLOW_PRIVATE_TARGETS else 'blocked'} | "
        f"audit: {config.AUDIT_PATH if config.AUDIT_ENABLED else 'disabled'}",
        file=sys.stderr,
        flush=True,
    )


if __name__ == "__main__":
    if "--manifest" in sys.argv:
        print(render_manifest(build_manifest(TOOLS), config.VERSION))
    elif "--verify-audit" in sys.argv:
        intact, summary = audit.verify_chain()
        print(("✅ " if intact else "🔴 ") + summary)
        sys.exit(0 if intact else 1)
    else:
        _startup_banner()
        mcp.run(transport="stdio")
