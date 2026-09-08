"""Tool-manifest integrity and audit verification.

Rationale: in MCP, a tool's *description* is an instruction that the model
reads and acts on. Changing a description silently changes agent behaviour
without changing any calling code — the "rug pull" / tool-poisoning class of
attack. Microsoft's guidance frames a description change as equivalent to a
dependency update: something to review before it ships.

This module computes a digest over every tool's name, description and input
schema. Pin it in your client config or CI and any change to what the model is
told this server can do becomes a visible diff instead of a silent one.
"""

from __future__ import annotations

import hashlib
import inspect
import json
from typing import Any, Callable


def tool_fingerprint(fn: Callable[..., Any]) -> dict[str, Any]:
    """Describe one tool the way an MCP client would see it."""
    signature = inspect.signature(fn)
    params = {
        name: {
            "annotation": str(param.annotation),
            "default": "<required>" if param.default is inspect.Parameter.empty else repr(param.default),
        }
        for name, param in signature.parameters.items()
    }
    return {
        "name": fn.__name__,
        "description": inspect.getdoc(fn) or "",
        "parameters": params,
    }


def build_manifest(tools: list[Callable[..., Any]]) -> dict[str, Any]:
    entries = sorted((tool_fingerprint(t) for t in tools), key=lambda e: e["name"])
    canonical = json.dumps(entries, sort_keys=True, separators=(",", ":"))
    return {
        "tool_count": len(entries),
        "digest": hashlib.sha256(canonical.encode("utf-8")).hexdigest(),
        "tools": [
            {"name": e["name"], "digest": hashlib.sha256(
                json.dumps(e, sort_keys=True, separators=(",", ":")).encode("utf-8")
            ).hexdigest()[:16]}
            for e in entries
        ],
    }


def render_manifest(manifest: dict[str, Any], version: str) -> str:
    out = "## Tool manifest\n\n"
    out += f"**Server version:** {version}\n\n"
    out += f"**Manifest digest (SHA-256):** `{manifest['digest']}`\n\n"
    out += "| Tool | Digest |\n|---|---|\n"
    for entry in manifest["tools"]:
        out += f"| `{entry['name']}` | `{entry['digest']}` |\n"
    out += "\n"
    out += (
        "> Pin the manifest digest in your client config or CI. In MCP, a tool "
        "description is an instruction the model follows, so a changed description "
        "changes agent behaviour with no code change anywhere. If this digest moves "
        "and you did not change the tools, stop and find out why.\n"
    )
    return out
