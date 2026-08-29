"""
Standalone test: directly call the analyze_hash function (bypassing MCP transport)
to verify VirusTotal integration works end-to-end.

Usage:
    VIRUSTOTAL_API_KEY=<your-key> python _test_analyze.py
"""
import asyncio
import os
import re
import httpx

VT_API_KEY = os.environ.get("VIRUSTOTAL_API_KEY", "")
TIMEOUT = httpx.Timeout(15.0)


async def analyze_hash_test(hash_val: str) -> str:
    trimmed = hash_val.strip()
    hash_types = {32: "MD5", 40: "SHA-1", 56: "SHA-224", 64: "SHA-256", 96: "SHA-384", 128: "SHA-512"}
    is_hex = bool(re.fullmatch(r"[0-9a-fA-F]+", trimmed))
    detected_type = hash_types.get(len(trimmed), f"Unknown ({len(trimmed)} hex chars)") if is_hex else "Not a valid hex hash"

    report = "## Hash Analysis Report\n\n"
    report += f"**Hash:** `{trimmed}`\n"
    report += f"**Detected Type:** {detected_type}\n"
    report += f"**Length:** {len(trimmed)} characters\n\n"

    if not is_hex:
        return report + "Input does not appear to be a valid hexadecimal hash."

    if not VT_API_KEY:
        return report + "> ℹ️ Set VIRUSTOTAL_API_KEY env var to enable VirusTotal lookup.\n"

    try:
        async with httpx.AsyncClient(timeout=TIMEOUT, follow_redirects=True) as client:
            res = await client.get(
                f"https://www.virustotal.com/api/v3/files/{trimmed}",
                headers={"x-apikey": VT_API_KEY},
            )

        if res.status_code == 404:
            report += "### VirusTotal\n\nHash NOT FOUND in VirusTotal database — no known threat associations.\n"
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
            report += f"**File Size:** {size/1024:.1f} KB\n" if isinstance(size, int) else f"**File Size:** {size}\n"
            report += f"**Harmless:** {harmless} | **Undetected:** {undetected}\n"
            report += f"**VT Link:** {vt_link}\n"
        else:
            report += f"### VirusTotal\n\nAPI returned status {res.status_code}.\n"
    except Exception as e:
        report += f"### VirusTotal\n\nRequest failed: {e}\n"

    return report


if __name__ == "__main__":
    result = asyncio.run(analyze_hash_test("44d88612fea8a8f36de82e1278abb02f"))
    print(result)
