"""File-hash identification and VirusTotal reputation enrichment."""

from __future__ import annotations

import re

from .. import config
from ..httpclient import cache_get, cache_put, describe_error, fetch
from ..safety import inline

HASH_TYPES = {32: "MD5", 40: "SHA-1", 56: "SHA-224", 64: "SHA-256", 96: "SHA-384", 128: "SHA-512"}

# MD5 and SHA-1 are still the lingua franca of threat feeds, but they are
# collision-broken: an attacker can craft a benign file matching a known-good
# hash. Worth saying out loud in the output rather than only in a README.
WEAK_ALGOS = {"MD5", "SHA-1"}


def identify(value: str) -> tuple[bool, str]:
    trimmed = value.strip()
    is_hex = bool(re.fullmatch(r"[0-9a-fA-F]+", trimmed))
    if not is_hex:
        return False, "not a hexadecimal string"
    return True, HASH_TYPES.get(len(trimmed), f"unrecognised length ({len(trimmed)} hex chars)")


async def analyze_hash(file_hash: str) -> str:
    """Identify a file hash's algorithm and look up its VirusTotal reputation.

    Reports the detection ratio across antivirus engines, the file type, and
    whether the hash algorithm itself is collision-broken. Requires
    VIRUSTOTAL_API_KEY for the reputation half; identification works offline.

    Args:
        file_hash: Hex file hash — MD5, SHA-1, SHA-224, SHA-256, SHA-384 or SHA-512.
    """
    trimmed = file_hash.strip()
    is_hex, detected = identify(trimmed)

    out = "## Hash analysis\n\n"
    out += "| Field | Value |\n|---|---|\n"
    out += f"| Input | `{trimmed[:140]}` |\n"
    out += f"| Algorithm | {detected} |\n"
    out += f"| Length | {len(trimmed)} chars |\n\n"

    if not is_hex:
        return out + "Input is not a valid hex hash, so no lookup was attempted.\n"

    if detected in WEAK_ALGOS:
        out += (
            f"> ⚠️ {detected} is collision-broken. It is fine as a lookup key against "
            "existing threat feeds, but never treat a matching "
            f"{detected} as proof that two files are identical.\n\n"
        )

    if not config.VT_API_KEY:
        return out + (
            "> ℹ️ `VIRUSTOTAL_API_KEY` is not set, so no reputation lookup ran. "
            "Identification above is purely local.\n"
        )

    cache_key = f"vt:{trimmed.lower()}"
    cached = cache_get(cache_key)
    if cached:
        return out + cached + "\n> 🗃️ Served from local cache.\n"

    try:
        response, _ = await fetch(
            f"https://www.virustotal.com/api/v3/files/{trimmed}",
            headers={"x-apikey": config.VT_API_KEY},
        )
    except Exception as exc:  # noqa: BLE001 — surfaced as text, never raised at the model
        return out + describe_error(exc) + "\n"

    if response.status_code == 404:
        section = (
            "### VirusTotal\n\n"
            "Hash is **not present** in VirusTotal.\n\n"
            "> This means *unknown*, not *clean*. Freshly built malware and targeted "
            "samples are routinely absent from public repositories.\n"
        )
        cache_put(cache_key, section)
        return out + section

    if response.status_code == 401:
        return out + "🔑 VirusTotal rejected the API key (HTTP 401). Check `VIRUSTOTAL_API_KEY`.\n"
    if response.status_code == 429:
        return out + "⏳ VirusTotal quota exhausted (HTTP 429). The free tier allows 4 requests/min.\n"
    if response.status_code != 200:
        return out + f"⚠️ VirusTotal returned HTTP {response.status_code}.\n"

    attributes = response.json().get("data", {}).get("attributes", {})
    stats = attributes.get("last_analysis_stats", {})
    malicious = int(stats.get("malicious", 0))
    suspicious = int(stats.get("suspicious", 0))
    harmless = int(stats.get("harmless", 0))
    undetected = int(stats.get("undetected", 0))
    total = malicious + suspicious + harmless + undetected

    verdict = (
        "🔴 HIGH — broad multi-engine consensus" if malicious > 10
        else "🟠 SUSPICIOUS — some engines flag it; check which ones before acting" if malicious > 0
        else "🟢 No detections — still verify context before whitelisting"
    )

    section = "### VirusTotal reputation\n\n"
    section += f"**Assessment:** {verdict}\n\n"
    section += "| Field | Value |\n|---|---|\n"
    section += f"| Detections | {malicious} malicious / {suspicious} suspicious of {total} engines |\n"
    section += f"| Harmless / undetected | {harmless} / {undetected} |\n"
    # File names and type strings are submitter-controlled: sanitise them.
    section += f"| Reported name | {inline(attributes.get('meaningful_name'))} |\n"
    section += f"| File type | {inline(attributes.get('type_description'))} |\n"
    size = attributes.get("size")
    section += f"| Size | {size / 1024:.1f} KB |\n" if isinstance(size, int) else "| Size | N/A |\n"
    section += f"| Pivot | https://www.virustotal.com/gui/file/{trimmed} |\n\n"
    section += (
        "> Detection names and file names come from submitters and vendors and are "
        "attacker-influenceable. Use them as leads, not as ground truth.\n"
    )

    cache_put(cache_key, section)
    return out + section
