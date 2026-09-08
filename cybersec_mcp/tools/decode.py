"""Payload decoder for obfuscated strings found in phishing, malware and CTFs.

Two things v1 got wrong and this fixes:

* auto mode printed a ROT13 rendering of everything, including binary garbage;
* it decoded one layer only, while real payloads nest (base64 → gzip → URL).

It also defangs anything that looks like a live URL or IP, because decoded
payloads routinely contain C2 addresses and this output ends up pasted into
chat clients that auto-fetch link previews.
"""

from __future__ import annotations

import base64
import binascii
import codecs
import gzip
import re
import zlib
from urllib.parse import unquote

from ..safety import defang, sanitize

MAX_DEPTH = 4
IOC_RE = re.compile(r"(https?://\S+|\b(?:\d{1,3}\.){3}\d{1,3}\b|\b[a-z0-9-]+\.[a-z]{2,24}\b)", re.I)

SUSPICIOUS = (
    (re.compile(r"powershell|-enc\b|-nop\b|IEX|Invoke-Expression", re.I), "PowerShell execution"),
    (re.compile(r"cmd\.exe|/c\s|certutil|bitsadmin|mshta|rundll32", re.I), "LOLBin usage"),
    (re.compile(r"eval\(|atob\(|document\.write|fromCharCode", re.I), "JavaScript evaluation"),
    (re.compile(r"/bin/(ba)?sh|nc\s+-e|\|\s*(ba|z|k)?sh\b", re.I), "shell download-and-run"),
    (re.compile(r"\b(curl|wget)\s+(-\S+\s+)*(https?://|ftp://)", re.I), "remote payload retrieval"),
    (re.compile(r"<script|onerror=|javascript:", re.I), "HTML/JS injection"),
    (re.compile(r"(union\s+select|or\s+1=1|--\s*$)", re.I), "SQL injection"),
    (re.compile(r"\.\./\.\./|%2e%2e%2f", re.I), "path traversal"),
)


def _ascii_printable_ratio(text: str) -> float:
    if not text:
        return 0.0
    return sum(1 for c in text if (32 <= ord(c) < 127) or c in "\n\r\t") / len(text)


def _plausible(text: str) -> bool:
    """Is this decode a real result, or coincidental noise?

    Base64 is dense enough that arbitrary input decodes *to something* roughly
    three quarters of the time. Python's ``str.isprintable`` is no help here
    because it returns True for CJK mojibake, which is exactly what random
    bytes produce when they happen to be valid UTF-8.

    So the bar is ASCII: at least 85% of the result must be printable ASCII,
    and it must contain a real word-like run. Known trade-off — this will
    reject a genuine payload written entirely in a non-Latin script. That is
    the right way round for malware and CTF work, where payloads are
    overwhelmingly ASCII, and it kills the false positives that made v1's
    auto mode unusable.
    """
    if not text or len(text) < 4:
        return False
    if _ascii_printable_ratio(text) < 0.85:
        return False
    return bool(re.search(r"[A-Za-z0-9]{3,}", text))


def try_base64(value: str) -> str | None:
    stripped = re.sub(r"\s+", "", value)
    if len(stripped) < 8 or not re.fullmatch(r"[A-Za-z0-9+/=_-]+", stripped):
        return None
    candidate = stripped.replace("-", "+").replace("_", "/")
    candidate += "=" * (-len(candidate) % 4)
    try:
        raw = base64.b64decode(candidate, validate=True)
    except (binascii.Error, ValueError):
        return None
    for decoder in ("utf-8", "utf-16-le"):
        try:
            text = raw.decode(decoder)
        except UnicodeDecodeError:
            continue
        if _plausible(text):
            return text
    return None


def try_hex(value: str) -> str | None:
    cleaned = re.sub(r"\s+|0x|\\x", "", value, flags=re.I)
    if len(cleaned) < 6 or len(cleaned) % 2 or not re.fullmatch(r"[0-9a-fA-F]+", cleaned):
        return None
    try:
        text = bytes.fromhex(cleaned).decode("utf-8")
    except (ValueError, UnicodeDecodeError):
        return None
    return text if _plausible(text) else None


def try_url(value: str) -> str | None:
    if "%" not in value and "+" not in value:
        return None
    decoded = unquote(value)
    return decoded if decoded != value and _plausible(decoded) else None


def try_rot13(value: str) -> str | None:
    if not re.search(r"[a-zA-Z]", value):
        return None
    decoded = codecs.encode(value, "rot_13")
    # Only report ROT13 when it produces something more word-like than the input.
    common = re.compile(r"\b(the|and|http|for|you|this|with|from|user|pass|admin)\b", re.I)
    if len(common.findall(decoded)) > len(common.findall(value)):
        return decoded
    return None


def try_gzip(value: str) -> str | None:
    stripped = re.sub(r"\s+", "", value)
    try:
        raw = base64.b64decode(stripped + "=" * (-len(stripped) % 4), validate=True)
    except (binascii.Error, ValueError):
        return None
    for decompress in (gzip.decompress, zlib.decompress, lambda b: zlib.decompress(b, -15)):
        try:
            text = decompress(raw).decode("utf-8", "replace")
        except Exception:  # noqa: BLE001, S112 — wrong compression format, try the next
            continue
        if _plausible(text):
            return text
    return None


DECODERS = {
    "base64": try_base64,
    "gzip": try_gzip,
    "hex": try_hex,
    "url": try_url,
    "rot13": try_rot13,
}

# A base64 run sitting inside a larger string — the shape of every real
# `powershell -enc <blob>`, `certutil -decode`, or `atob("...")` payload.
# 16 chars is the floor: shorter runs are mostly ordinary words and filenames.
_EMBEDDED_RE = re.compile(r"[A-Za-z0-9+/=_-]{16,}")


def find_embedded(text: str) -> list[tuple[str, str]]:
    """Decode base64-looking runs embedded inside a longer string.

    The layer loop only decodes when the *entire* string is encoded, which is
    the wrong shape for real command lines: the blob is an argument, not the
    whole payload. This finds those runs and decodes them separately.
    """
    results: list[tuple[str, str]] = []
    for match in _EMBEDDED_RE.finditer(text):
        blob = match.group(0)
        if blob == text.strip():
            continue  # the layer loop already handled the whole-string case
        for decoder in (try_base64, try_gzip, try_hex):
            decoded = decoder(blob)
            if decoded and decoded != blob:
                results.append((blob, decoded))
                break
        if len(results) >= 6:
            break
    return results


async def decode_payload(payload: str, encoding: str = "auto", defang_output: bool = True) -> str:
    """Decode an obfuscated payload, peeling nested layers until nothing decodes.

    Handles base64 (standard and URL-safe), base64+gzip/zlib, hex, URL encoding
    and ROT13. In auto mode it recurses up to 4 layers and only reports decodes
    that produce plausible text. It also decodes encoded runs found *inside* the
    result rather than wrapping it, which is the shape of `powershell -enc
    <blob>` and similar command lines. Any URLs, domains or IPs in the output are
    defanged so they cannot be clicked or auto-previewed.

    Args:
        payload: The encoded string to decode.
        encoding: base64 | gzip | hex | url | rot13 | auto (default auto).
        defang_output: Neutralise URLs and IPs in the output. Keep this on unless
            you are feeding the result to another parser.
    """
    if encoding not in {*DECODERS, "auto"}:
        return f"❌ Unknown encoding `{encoding}`. Use one of: {', '.join(DECODERS)}, auto."

    original = payload.strip()
    out = "## Payload decoder\n\n"
    out += "| Field | Value |\n|---|---|\n"
    out += f"| Input length | {len(original)} chars |\n"
    out += f"| Mode | {encoding} |\n\n"

    layers: list[tuple[str, str]] = []

    if encoding == "auto":
        current = original
        for _ in range(MAX_DEPTH):
            for name, decoder in DECODERS.items():
                result = decoder(current)
                if result and result != current:
                    layers.append((name, result))
                    current = result
                    break
            else:
                break
    else:
        result = DECODERS[encoding](original)
        if result:
            layers.append((encoding, result))

    if not layers:
        out += (
            "No layer decoded to plausible text.\n\n"
            "> Nothing decoded is a result, not a failure — it usually means the input is "
            "already plaintext, is encrypted, or uses an encoding not covered here "
            "(base32, XOR with a key, custom packers).\n"
        )
        return out

    out += f"### Decoded {len(layers)} layer(s)\n\n"
    for depth, (name, text) in enumerate(layers, 1):
        shown = text if len(text) <= 2000 else text[:2000] + "\n[... truncated ...]"
        if defang_output:
            shown = defang(shown)
        clean = sanitize(shown, limit=2100)
        out += f"**Layer {depth} — {name}**\n"
        out += clean.block(f"decoded-layer-{depth}")
        out += "\n"

    final = layers[-1][1]

    embedded = find_embedded(final) if encoding in {"auto", "base64"} else []
    if embedded:
        out += "### Embedded encoded blobs\n\n"
        out += (
            "Encoded runs found *inside* the decoded text rather than wrapping it — "
            "the shape of `powershell -enc <blob>` and similar.\n\n"
        )
        for blob, decoded in embedded:
            shown = defang(decoded) if defang_output else decoded
            out += f"**`{blob[:60]}{'…' if len(blob) > 60 else ''}`** decodes to:\n"
            out += sanitize(shown, limit=1200).block("embedded-decoded")
            out += "\n"
            final += "\n" + decoded  # feed it into IOC and indicator extraction

    findings = [label for pattern, label in SUSPICIOUS if pattern.search(final)]
    if findings:
        out += "### Indicators in the decoded content\n\n"
        out += "\n".join(f"- 🔴 {f}" for f in sorted(set(findings))) + "\n\n"

    iocs = sorted({m.group(0) for m in IOC_RE.finditer(final)})[:12]
    if iocs:
        out += "### Extracted IOCs (defanged)\n\n"
        out += "\n".join(f"- `{defang(i)}`" for i in iocs) + "\n\n"
        if defang_output:
            out += "> URLs and IPs above are defanged (`hxxp`, `[.]`). Re-fang only inside an isolated analysis VM.\n"
    return out
