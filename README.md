# 🔐 CyberSec MCP Server

> An **Information Security MCP Server** built with Python — demonstrating real-world infosec skills
> using the Model Context Protocol (MCP) to give AI assistants native cybersecurity tooling.

---

## What is MCP?

The **Model Context Protocol** (MCP) is an open standard that lets you connect AI assistants
(like Claude, Bob, etc.) to external tools, APIs, and data sources via a structured server protocol.
This project exposes 7 professional-grade infosec tools directly inside an AI assistant.

---

## 🛠️ Tools

| Tool | Description |
|---|---|
| `analyze_hash` | Identifies hash type (MD5/SHA-1/SHA-256/SHA-512) + VirusTotal threat intel |
| `check_cve` | Queries NIST NVD for CVE details, CVSS score, attack vector, and references |
| `scan_headers` | Audits HTTP security headers (CSP, HSTS, X-Frame-Options, etc.) with a letter grade |
| `whois_lookup` | RDAP WHOIS + passive DNS + IP geolocation OSINT on any domain |
| `decode_payload` | Decodes Base64 / Hex / URL / ROT13 encoded payloads (CTF & malware analysis) |
| `password_strength` | NIST SP 800-63b password analysis — entropy, character diversity, weak patterns |
| `generate_threat_report` | Generates structured TI reports with MITRE ATT&CK mapping and NIST CSF guidance |

---

## 🚀 Quick Start

### Prerequisites

- Python 3.11+
- A [VirusTotal API key](https://www.virustotal.com/gui/join-us) (free tier works)

### Install

```bash
git clone https://github.com/fa1829/cybersec-mcp
cd cybersec-mcp
pip install -r requirements.txt
```

### Register in Bob / Claude Desktop

Add to your `.bob/mcp.json` (workspace) or `~/.bob/settings/mcp.json` (global):

```json
{
  "mcpServers": {
    "cybersec-mcp": {
      "command": "python",
      "args": ["/absolute/path/to/cybersec-mcp/server.py"],
      "env": {
        "VIRUSTOTAL_API_KEY": "<your-vt-api-key>"
      }
    }
  }
}
```

---

## 💡 Example Prompts

Once connected, you can ask your AI assistant things like:

- *"Analyze this hash: 44d88612fea8a8f36de82e1278abb02f"*
- *"Check CVE-2021-44228 (Log4Shell) for me"*
- *"Audit the security headers on https://github.com"*
- *"Do a WHOIS lookup on malicious-domain.com"*
- *"Decode this base64 payload: SGVsbG8gV29ybGQ="*
- *"How strong is the password 'P@ssw0rd123'?"*
- *"Generate a threat report for a ransomware incident targeting our HR system"*

---

## 🧠 Skills Demonstrated

- Threat Intelligence & OSINT (VirusTotal, RDAP, DNS-over-HTTPS)
- Vulnerability Research (NIST NVD, CVSS scoring)
- Defensive Security (HTTP header auditing, security grading)
- Malware Analysis tradecraft (hash identification, payload decoding)
- NIST SP 800-63b password security guidelines
- MITRE ATT&CK Framework mapping
- NIST Cybersecurity Framework (CSF) incident response
- MCP server development (Python, async, FastMCP)

---

## 📚 References

- [MITRE ATT&CK](https://attack.mitre.org)
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)
- [NIST SP 800-63b](https://pages.nist.gov/800-63-3/sp800-63b.html)
- [NIST NVD](https://nvd.nist.gov)
- [VirusTotal API](https://developers.virustotal.com)
- [Model Context Protocol](https://modelcontextprotocol.io)

---

## License

MIT — use freely, attribution appreciated.
