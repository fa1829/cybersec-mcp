"""Tamper-evident audit log of every tool invocation.

OWASP MCP Top 10 lists "lack of audit and telemetry" as its own risk category:
when an agent calls tools autonomously, an unlogged call is an action nobody
can reconstruct afterwards.

Each record carries the SHA-256 of the previous record, so any edit or deletion
in the middle of the file breaks the chain and ``verify_chain`` reports where.
This is tamper-*evident*, not tamper-*proof*: an attacker who can write the file
can recompute the whole chain. Ship the file to append-only storage if you need
more than evidence of local edits.
"""

from __future__ import annotations

import hashlib
import json
import os
import time
from pathlib import Path
from typing import Any

from . import config

GENESIS = "0" * 64

# Arguments that must never reach disk, in full or in part.
_NEVER_LOG = {"password"}


def _digest(payload: str) -> str:
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _redact_args(args: dict[str, Any]) -> dict[str, Any]:
    """Log the shape of an argument set without logging its secrets."""
    out: dict[str, Any] = {}
    for key, value in args.items():
        if key in _NEVER_LOG:
            out[key] = f"<redacted len={len(str(value))}>"
        elif isinstance(value, str) and len(value) > 256:
            out[key] = value[:256] + "…"
        else:
            out[key] = value
    return out


def _last_hash(path: Path) -> str:
    if not path.exists() or path.stat().st_size == 0:
        return GENESIS
    with path.open("rb") as handle:
        handle.seek(0, os.SEEK_END)
        size = handle.tell()
        block = min(size, 8192)
        handle.seek(size - block)
        tail = handle.read().decode("utf-8", "replace").strip().splitlines()
    for line in reversed(tail):
        try:
            return json.loads(line)["entry_hash"]
        except (ValueError, KeyError):
            continue
    return GENESIS


def record(
    tool: str,
    args: dict[str, Any],
    *,
    outcome: str,
    duration_ms: int,
    flags: list[str] | None = None,
    detail: str = "",
) -> str | None:
    """Append one chained record. Returns its hash, or None if disabled."""
    if not config.AUDIT_ENABLED:
        return None

    path = config.AUDIT_PATH
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        previous = _last_hash(path)
        entry: dict[str, Any] = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "server": f"{config.SERVER_NAME}/{config.VERSION}",
            "tool": tool,
            "args": _redact_args(args),
            "outcome": outcome,
            "duration_ms": duration_ms,
            "flags": flags or [],
            "detail": detail[:300],
            "prev_hash": previous,
        }
        entry["entry_hash"] = _digest(previous + json.dumps(entry, sort_keys=True))
        with path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(entry) + "\n")
        return entry["entry_hash"]
    except OSError:
        # An unwritable audit path must not take the server down, but it is
        # visible on stderr so the operator notices.
        print(f"[cybersec-mcp] WARNING: audit log unwritable at {path}", flush=True)
        return None


def verify_chain(path: Path | None = None) -> tuple[bool, str]:
    """Recompute the chain. Returns (intact, human-readable summary)."""
    path = path or config.AUDIT_PATH
    if not path.exists():
        return True, f"No audit log at {path} — nothing to verify."

    previous = GENESIS
    count = 0
    with path.open(encoding="utf-8") as handle:
        for lineno, line in enumerate(handle, 1):
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
            except ValueError:
                return False, f"Line {lineno}: not valid JSON — log is corrupt."
            stored = entry.pop("entry_hash", None)
            if entry.get("prev_hash") != previous:
                return False, f"Line {lineno}: prev_hash mismatch — a record was altered or removed."
            expected = _digest(previous + json.dumps(entry, sort_keys=True))
            if stored != expected:
                return False, f"Line {lineno}: entry_hash mismatch — this record was modified."
            previous = stored
            count += 1
    return True, f"Chain intact across {count} record(s); head = {previous[:16]}…"
