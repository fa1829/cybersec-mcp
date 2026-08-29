"""
Minimal VirusTotal connectivity test.

Usage:
    VIRUSTOTAL_API_KEY=<your-key> python _test_vt.py
"""
import asyncio
import os
import re
import httpx

VT_API_KEY = os.environ.get("VIRUSTOTAL_API_KEY", "")


async def main():
    if not VT_API_KEY:
        print("⚠️  Set VIRUSTOTAL_API_KEY env var first.")
        return

    h = "44d88612fea8a8f36de82e1278abb02f"
    hash_types = {32: "MD5", 40: "SHA-1", 56: "SHA-224", 64: "SHA-256", 96: "SHA-384", 128: "SHA-512"}
    is_hex = bool(re.fullmatch(r"[0-9a-fA-F]+", h))
    detected = hash_types.get(len(h), "Unknown") if is_hex else "Invalid"
    print(f"Hash: {h}")
    print(f"Type: {detected} ({len(h)} chars)")

    async with httpx.AsyncClient(timeout=httpx.Timeout(15.0), follow_redirects=True) as client:
        res = await client.get(
            f"https://www.virustotal.com/api/v3/files/{h}",
            headers={"x-apikey": VT_API_KEY},
        )
        print(f"VT HTTP Status: {res.status_code}")
        if res.status_code == 200:
            data = res.json()
            attrs = data.get("data", {}).get("attributes", {})
            stats = attrs.get("last_analysis_stats", {})
            print(f"Malicious: {stats.get('malicious', 0)}")
            print(f"Suspicious: {stats.get('suspicious', 0)}")
            print(f"Harmless: {stats.get('harmless', 0)}")
            print(f"Undetected: {stats.get('undetected', 0)}")
            print(f"File name: {attrs.get('meaningful_name', 'N/A')}")
            print(f"File type: {attrs.get('type_description', 'N/A')}")
            size = attrs.get("size", "N/A")
            print(f"File size: {size/1024:.1f} KB" if isinstance(size, int) else f"File size: {size}")
        elif res.status_code == 404:
            print("NOT FOUND in VT database — hash is clean/unknown")
        else:
            print(f"Error response: {res.text[:300]}")


if __name__ == "__main__":
    asyncio.run(main())
