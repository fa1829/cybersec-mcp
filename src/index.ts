#!/usr/bin/env node
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";

const VT_API_KEY = process.env.VIRUSTOTAL_API_KEY ?? "";

const server = new McpServer({
  name: "cybersec-mcp",
  version: "1.0.0",
});

// ─────────────────────────────────────────────
// UTILITY HELPERS
// ─────────────────────────────────────────────

function ok(text: string) {
  return { content: [{ type: "text" as const, text }] };
}

function err(text: string) {
  return { content: [{ type: "text" as const, text }], isError: true };
}

async function httpGet(url: string, headers: Record<string, string> = {}): Promise<Response> {
  return fetch(url, { headers, signal: AbortSignal.timeout(10_000) });
}

// ─────────────────────────────────────────────
// TOOL 1 — analyze-hash
// Identifies hash type + VirusTotal reputation check
// ─────────────────────────────────────────────

server.tool(
  "analyze-hash",
  "Identify the hash algorithm type (MD5, SHA-1, SHA-256, etc.) and optionally query VirusTotal for reputation/threat intelligence on the hash.",
  {
    hash: z.string().describe("The hash string to analyze (e.g. MD5, SHA-1, SHA-256 hash of a file or string)"),
  },
  async ({ hash }) => {
    const trimmed = hash.trim();

    // Identify hash type by length
    const hashTypes: Record<number, string> = {
      32: "MD5",
      40: "SHA-1",
      56: "SHA-224",
      64: "SHA-256",
      96: "SHA-384",
      128: "SHA-512",
    };

    const isHex = /^[0-9a-fA-F]+$/.test(trimmed);
    const detectedType = isHex ? (hashTypes[trimmed.length] ?? `Unknown (${trimmed.length} hex chars)`) : "Not a valid hex hash";

    let report = `## Hash Analysis Report\n\n`;
    report += `**Hash:** \`${trimmed}\`\n`;
    report += `**Detected Type:** ${detectedType}\n`;
    report += `**Length:** ${trimmed.length} characters\n\n`;

    if (!isHex) {
      return ok(report + "⚠️ Input does not appear to be a valid hexadecimal hash.");
    }

    // VirusTotal lookup
    if (!VT_API_KEY) {
      report += `> ℹ️ VirusTotal API key not configured — skipping reputation check.\n`;
      return ok(report);
    }

    try {
      const vtRes = await httpGet(
        `https://www.virustotal.com/api/v3/files/${trimmed}`,
        { "x-apikey": VT_API_KEY }
      );

      if (vtRes.status === 404) {
        report += `### VirusTotal\n\n✅ Hash **not found** in VirusTotal database — no known threat associations.\n`;
      } else if (vtRes.status === 200) {
        const data = (await vtRes.json()) as any;
        const stats = data?.data?.attributes?.last_analysis_stats ?? {};
        const malicious: number = stats.malicious ?? 0;
        const suspicious: number = stats.suspicious ?? 0;
        const harmless: number = stats.harmless ?? 0;
        const undetected: number = stats.undetected ?? 0;
        const total = malicious + suspicious + harmless + undetected;
        const name = data?.data?.attributes?.meaningful_name ?? "N/A";
        const fileType = data?.data?.attributes?.type_description ?? "N/A";
        const size = data?.data?.attributes?.size ?? "N/A";
        const vtLink = `https://www.virustotal.com/gui/file/${trimmed}`;

        const threatLevel = malicious > 10 ? "🔴 HIGH THREAT" : malicious > 0 ? "🟠 SUSPICIOUS" : "🟢 CLEAN";

        report += `### VirusTotal Reputation\n\n`;
        report += `**Threat Level:** ${threatLevel}\n`;
        report += `**Detections:** ${malicious} malicious / ${suspicious} suspicious out of ${total} engines\n`;
        report += `**File Name:** ${name}\n`;
        report += `**File Type:** ${fileType}\n`;
        report += `**File Size:** ${typeof size === "number" ? (size / 1024).toFixed(1) + " KB" : size}\n`;
        report += `**Harmless:** ${harmless} | **Undetected:** ${undetected}\n`;
        report += `**VT Link:** ${vtLink}\n`;
      } else {
        report += `### VirusTotal\n\n⚠️ API returned status ${vtRes.status}.\n`;
      }
    } catch (e) {
      report += `### VirusTotal\n\n⚠️ Request failed: ${e instanceof Error ? e.message : String(e)}\n`;
    }

    return ok(report);
  }
);

// ─────────────────────────────────────────────
// TOOL 2 — check-cve
// Queries NVD (NIST) for CVE details
// ─────────────────────────────────────────────

server.tool(
  "check-cve",
  "Look up a CVE ID from the NIST National Vulnerability Database (NVD) and return severity, CVSS score, description, affected products, and remediation guidance.",
  {
    cve_id: z.string().describe("CVE identifier, e.g. CVE-2021-44228 (Log4Shell)"),
  },
  async ({ cve_id }) => {
    const id = cve_id.trim().toUpperCase();

    if (!/^CVE-\d{4}-\d{4,}$/.test(id)) {
      return err(`❌ Invalid CVE format: "${id}". Expected format: CVE-YYYY-NNNNN`);
    }

    try {
      const res = await httpGet(
        `https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=${id}`
      );

      if (!res.ok) {
        return err(`NVD API returned HTTP ${res.status} for ${id}`);
      }

      const data = (await res.json()) as any;
      const vuln = data?.vulnerabilities?.[0]?.cve;

      if (!vuln) {
        return ok(`## ${id}\n\nℹ️ Not found in the NVD database.`);
      }

      const descriptions: any[] = vuln.descriptions ?? [];
      const description = descriptions.find((d: any) => d.lang === "en")?.value ?? "No description available.";

      const metrics = vuln.metrics ?? {};
      const cvss31 = metrics?.cvssMetricV31?.[0];
      const cvss30 = metrics?.cvssMetricV30?.[0];
      const cvss2 = metrics?.cvssMetricV2?.[0];
      const cvssData = cvss31 ?? cvss30 ?? cvss2;

      const score = cvssData?.cvssData?.baseScore ?? "N/A";
      const severity = cvssData?.cvssData?.baseSeverity ?? cvss2?.baseSeverity ?? "N/A";
      const vector = cvssData?.cvssData?.vectorString ?? "N/A";
      const attackVector = cvssData?.cvssData?.attackVector ?? "N/A";
      const privileges = cvssData?.cvssData?.privilegesRequired ?? "N/A";
      const userInteraction = cvssData?.cvssData?.userInteraction ?? "N/A";

      const published = vuln.published?.slice(0, 10) ?? "N/A";
      const modified = vuln.lastModified?.slice(0, 10) ?? "N/A";

      const references: any[] = vuln.references ?? [];
      const refLinks = references
        .slice(0, 5)
        .map((r: any) => `- ${r.url}`)
        .join("\n");

      const severityEmoji: Record<string, string> = {
        CRITICAL: "🔴",
        HIGH: "🟠",
        MEDIUM: "🟡",
        LOW: "🟢",
      };
      const sevEmoji = severityEmoji[severity?.toUpperCase()] ?? "⚪";

      let report = `## ${id}\n\n`;
      report += `**Severity:** ${sevEmoji} ${severity}\n`;
      report += `**CVSS Score:** ${score} / 10\n`;
      report += `**Vector String:** \`${vector}\`\n`;
      report += `**Attack Vector:** ${attackVector}\n`;
      report += `**Privileges Required:** ${privileges}\n`;
      report += `**User Interaction:** ${userInteraction}\n`;
      report += `**Published:** ${published} | **Last Modified:** ${modified}\n\n`;
      report += `### Description\n\n${description}\n\n`;
      if (refLinks) {
        report += `### References (top 5)\n\n${refLinks}\n\n`;
      }
      report += `### NVD Link\nhttps://nvd.nist.gov/vuln/detail/${id}\n`;

      return ok(report);
    } catch (e) {
      return err(`Failed to query NVD: ${e instanceof Error ? e.message : String(e)}`);
    }
  }
);

// ─────────────────────────────────────────────
// TOOL 3 — scan-headers
// Audits HTTP security headers of a URL
// ─────────────────────────────────────────────

server.tool(
  "scan-headers",
  "Fetch HTTP response headers from a URL and audit them for security best practices (CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, etc.).",
  {
    url: z.string().url().describe("The full URL to audit, e.g. https://example.com"),
  },
  async ({ url }) => {
    try {
      const res = await httpGet(url);
      const headers: Record<string, string> = {};
      res.headers.forEach((value, key) => {
        headers[key.toLowerCase()] = value;
      });

      type HeaderCheck = {
        header: string;
        present: boolean;
        value?: string;
        recommendation: string;
        severity: "HIGH" | "MEDIUM" | "LOW" | "INFO";
      };

      const checks: HeaderCheck[] = [
        {
          header: "Strict-Transport-Security",
          present: "strict-transport-security" in headers,
          value: headers["strict-transport-security"],
          recommendation: "Set: max-age=31536000; includeSubDomains; preload",
          severity: "HIGH",
        },
        {
          header: "Content-Security-Policy",
          present: "content-security-policy" in headers,
          value: headers["content-security-policy"],
          recommendation: "Define a restrictive CSP to prevent XSS and data injection attacks.",
          severity: "HIGH",
        },
        {
          header: "X-Frame-Options",
          present: "x-frame-options" in headers,
          value: headers["x-frame-options"],
          recommendation: "Set to DENY or SAMEORIGIN to prevent clickjacking.",
          severity: "MEDIUM",
        },
        {
          header: "X-Content-Type-Options",
          present: "x-content-type-options" in headers,
          value: headers["x-content-type-options"],
          recommendation: "Set to: nosniff",
          severity: "MEDIUM",
        },
        {
          header: "Referrer-Policy",
          present: "referrer-policy" in headers,
          value: headers["referrer-policy"],
          recommendation: "Set to: strict-origin-when-cross-origin or no-referrer",
          severity: "LOW",
        },
        {
          header: "Permissions-Policy",
          present: "permissions-policy" in headers,
          value: headers["permissions-policy"],
          recommendation: "Restrict browser features (camera, microphone, geolocation).",
          severity: "LOW",
        },
        {
          header: "X-XSS-Protection",
          present: "x-xss-protection" in headers,
          value: headers["x-xss-protection"],
          recommendation: "Legacy header — set to 0 (disabled) since CSP supersedes it.",
          severity: "INFO",
        },
      ];

      const missing = checks.filter((c) => !c.present);
      const present = checks.filter((c) => c.present);

      const highMissing = missing.filter((c) => c.severity === "HIGH").length;
      const medMissing = missing.filter((c) => c.severity === "MEDIUM").length;

      const grade =
        highMissing >= 2 ? "F" :
        highMissing === 1 ? "D" :
        medMissing >= 2 ? "C" :
        medMissing === 1 ? "B" : "A";

      let report = `## HTTP Security Header Audit\n\n`;
      report += `**Target:** ${url}\n`;
      report += `**Status:** HTTP ${res.status} ${res.statusText}\n`;
      report += `**Security Grade:** ${grade}\n\n`;

      report += `### ✅ Present Headers (${present.length})\n\n`;
      for (const c of present) {
        report += `**${c.header}**\n\`${c.value}\`\n\n`;
      }

      if (missing.length > 0) {
        report += `### ❌ Missing Headers (${missing.length})\n\n`;
        for (const c of missing) {
          const badge = c.severity === "HIGH" ? "🔴" : c.severity === "MEDIUM" ? "🟠" : "🟡";
          report += `${badge} **${c.header}** [${c.severity}]\n`;
          report += `> Recommendation: ${c.recommendation}\n\n`;
        }
      }

      report += `### Server Info\n\n`;
      const serverHeader = headers["server"] ?? headers["x-powered-by"];
      if (serverHeader) {
        report += `⚠️ Server fingerprint exposed: \`${serverHeader}\` — consider removing this header.\n`;
      } else {
        report += `✅ No server/technology fingerprinting headers detected.\n`;
      }

      return ok(report);
    } catch (e) {
      return err(`Failed to fetch headers: ${e instanceof Error ? e.message : String(e)}`);
    }
  }
);

// ─────────────────────────────────────────────
// TOOL 4 — whois-lookup
// Passive WHOIS + DNS recon on a domain
// ─────────────────────────────────────────────

server.tool(
  "whois-lookup",
  "Perform WHOIS and passive DNS reconnaissance on a domain. Returns registration info, registrar, name servers, creation/expiry dates, and IP geolocation via public APIs.",
  {
    domain: z.string().describe("The domain name to investigate, e.g. example.com"),
  },
  async ({ domain }) => {
    const cleaned = domain.trim().toLowerCase().replace(/^https?:\/\//, "").replace(/\/.*$/, "");

    try {
      // RDAP (modern WHOIS replacement by IANA)
      const rdapRes = await httpGet(`https://rdap.org/domain/${cleaned}`);
      let report = `## OSINT / WHOIS Report: ${cleaned}\n\n`;

      if (rdapRes.ok) {
        const rdap = (await rdapRes.json()) as any;
        const events: any[] = rdap.events ?? [];
        const getEvent = (type: string) =>
          events.find((e: any) => e.eventAction === type)?.eventDate?.slice(0, 10) ?? "N/A";

        const nameServers: string[] = (rdap.nameservers ?? []).map((ns: any) => ns.ldhName as string);
        const entities: any[] = rdap.entities ?? [];
        const registrar = entities.find((e: any) => (e.roles ?? []).includes("registrar"));
        const registrarName = registrar?.vcardArray?.[1]?.find((v: any) => v[0] === "fn")?.[3] ?? "N/A";

        report += `### Registration Details\n\n`;
        report += `**Domain:** ${rdap.ldhName ?? cleaned}\n`;
        report += `**Registrar:** ${registrarName}\n`;
        report += `**Status:** ${(rdap.status ?? []).join(", ") || "N/A"}\n`;
        report += `**Created:** ${getEvent("registration")}\n`;
        report += `**Updated:** ${getEvent("last changed")}\n`;
        report += `**Expires:** ${getEvent("expiration")}\n\n`;
        report += `**Name Servers:**\n${nameServers.map((ns) => `- ${ns}`).join("\n") || "N/A"}\n\n`;
      } else {
        report += `> ℹ️ RDAP lookup returned ${rdapRes.status} — domain may not exist or RDAP unsupported.\n\n`;
      }

      // DNS over HTTPS (Cloudflare)
      const dnsRes = await httpGet(
        `https://cloudflare-dns.com/dns-query?name=${cleaned}&type=A`,
        { Accept: "application/dns-json" }
      );

      if (dnsRes.ok) {
        const dns = (await dnsRes.json()) as any;
        const aRecords: string[] = (dns.Answer ?? [])
          .filter((r: any) => r.type === 1)
          .map((r: any) => r.data as string);

        report += `### DNS Resolution\n\n`;
        if (aRecords.length > 0) {
          report += `**A Records (IPv4):** ${aRecords.join(", ")}\n\n`;

          // IP Geolocation
          const ip = aRecords[0];
          const geoRes = await httpGet(`http://ip-api.com/json/${ip}?fields=status,country,regionName,city,isp,org,as`);
          if (geoRes.ok) {
            const geo = (await geoRes.json()) as any;
            if (geo.status === "success") {
              report += `### IP Intelligence: ${ip}\n\n`;
              report += `**Location:** ${geo.city}, ${geo.regionName}, ${geo.country}\n`;
              report += `**ISP:** ${geo.isp}\n`;
              report += `**Org:** ${geo.org}\n`;
              report += `**ASN:** ${geo.as}\n\n`;
            }
          }
        } else {
          report += `No A records found for ${cleaned}.\n\n`;
        }
      }

      return ok(report);
    } catch (e) {
      return err(`WHOIS lookup failed: ${e instanceof Error ? e.message : String(e)}`);
    }
  }
);

// ─────────────────────────────────────────────
// TOOL 5 — decode-payload
// Decodes Base64 / URL-encoded / hex strings
// ─────────────────────────────────────────────

server.tool(
  "decode-payload",
  "Decode obfuscated or encoded payloads commonly found in malware analysis, CTF challenges, and phishing emails. Supports Base64, URL encoding, hex, and ROT13.",
  {
    payload: z.string().describe("The encoded string to decode"),
    encoding: z
      .enum(["base64", "url", "hex", "rot13", "auto"])
      .default("auto")
      .describe("Encoding type. Use 'auto' to attempt all decodings automatically."),
  },
  async ({ payload, encoding }) => {
    const trimmed = payload.trim();
    let report = `## Payload Decoder\n\n`;
    report += `**Input:** \`${trimmed.slice(0, 100)}${trimmed.length > 100 ? "…" : ""}\`\n`;
    report += `**Mode:** ${encoding}\n\n`;

    function tryBase64(s: string): string | null {
      try {
        const decoded = Buffer.from(s, "base64").toString("utf8");
        // Check it's printable
        if (/[\x00-\x08\x0e-\x1f\x7f]/.test(decoded)) return null;
        return decoded;
      } catch {
        return null;
      }
    }

    function tryHex(s: string): string | null {
      const cleaned = s.replace(/\s+|0x/g, "");
      if (!/^[0-9a-fA-F]+$/.test(cleaned) || cleaned.length % 2 !== 0) return null;
      try {
        return Buffer.from(cleaned, "hex").toString("utf8");
      } catch {
        return null;
      }
    }

    function tryUrl(s: string): string | null {
      try {
        return decodeURIComponent(s);
      } catch {
        return null;
      }
    }

    function rot13(s: string): string {
      return s.replace(/[a-zA-Z]/g, (c) => {
        const base = c <= "Z" ? 65 : 97;
        return String.fromCharCode(((c.charCodeAt(0) - base + 13) % 26) + base);
      });
    }

    if (encoding === "base64" || encoding === "auto") {
      const result = tryBase64(trimmed);
      if (result) {
        report += `### Base64 Decoded\n\n\`\`\`\n${result}\n\`\`\`\n\n`;
        if (encoding !== "auto") return ok(report);
      } else if (encoding === "base64") {
        report += `❌ Invalid Base64 input.\n`;
        return ok(report);
      }
    }

    if (encoding === "hex" || encoding === "auto") {
      const result = tryHex(trimmed);
      if (result) {
        report += `### Hex Decoded\n\n\`\`\`\n${result}\n\`\`\`\n\n`;
        if (encoding !== "auto") return ok(report);
      } else if (encoding === "hex") {
        report += `❌ Invalid hex input.\n`;
        return ok(report);
      }
    }

    if (encoding === "url" || encoding === "auto") {
      const result = tryUrl(trimmed);
      if (result && result !== trimmed) {
        report += `### URL Decoded\n\n\`\`\`\n${result}\n\`\`\`\n\n`;
        if (encoding !== "auto") return ok(report);
      } else if (encoding === "url") {
        report += `⚠️ Input is already URL-decoded or contains no encoded characters.\n`;
        return ok(report);
      }
    }

    if (encoding === "rot13" || encoding === "auto") {
      const result = rot13(trimmed);
      report += `### ROT13 Decoded\n\n\`\`\`\n${result}\n\`\`\`\n\n`;
    }

    if (encoding === "auto") {
      report += `> ℹ️ Attempted all encodings in auto mode. Results shown above.`;
    }

    return ok(report);
  }
);

// ─────────────────────────────────────────────
// TOOL 6 — password-strength
// Analyzes password against NIST 800-63b guidelines
// ─────────────────────────────────────────────

server.tool(
  "password-strength",
  "Analyze password strength against NIST SP 800-63b guidelines. Checks length, entropy, character diversity, common patterns, and known breach indicators. Does NOT store or transmit the password.",
  {
    password: z.string().describe("The password to analyze (processed locally, never stored or transmitted)"),
  },
  async ({ password }) => {
    const len = password.length;

    // Character class checks
    const hasUpper = /[A-Z]/.test(password);
    const hasLower = /[a-z]/.test(password);
    const hasDigit = /[0-9]/.test(password);
    const hasSymbol = /[^A-Za-z0-9]/.test(password);
    const classCount = [hasUpper, hasLower, hasDigit, hasSymbol].filter(Boolean).length;

    // Entropy estimate (bits)
    const poolSize =
      (hasUpper ? 26 : 0) + (hasLower ? 26 : 0) + (hasDigit ? 10 : 0) + (hasSymbol ? 32 : 0);
    const entropy = poolSize > 0 ? Math.log2(poolSize) * len : 0;

    // Common weak patterns
    const weakPatterns = [
      { pattern: /^(.)\1+$/, label: "All same character" },
      { pattern: /^(012|123|234|345|456|567|678|789|890|987|876|765|654|543|432|321|210)/i, label: "Sequential numbers" },
      { pattern: /^(abc|bcd|cde|def|efg|fgh|ghi|hij|ijk|jkl|klm|lmn|mno|nop|opq|pqr|qrs|rst|stu|tuv|uvw|vwx|wxy|xyz)/i, label: "Sequential letters" },
      { pattern: /password|passwd|p@ssw0rd|pa55word|letmein|welcome|admin|login|qwerty|iloveyou/i, label: "Common password keyword" },
    ];

    const triggeredPatterns = weakPatterns.filter((wp) => wp.pattern.test(password)).map((wp) => wp.label);

    // NIST 800-63b score
    let score = 0;
    if (len >= 8) score += 1;
    if (len >= 12) score += 1;
    if (len >= 16) score += 1;
    if (classCount >= 3) score += 1;
    if (entropy >= 50) score += 1;
    if (triggeredPatterns.length === 0) score += 1;

    const strengthLabel = score >= 5 ? "💪 STRONG" : score >= 3 ? "⚠️ MODERATE" : "🔴 WEAK";

    let report = `## Password Strength Analysis\n\n`;
    report += `> 🔒 Password is analyzed **locally**. It is never sent over the network.\n\n`;
    report += `**Length:** ${len} characters\n`;
    report += `**Entropy (estimate):** ${entropy.toFixed(1)} bits\n`;
    report += `**Character Classes Used:** ${classCount}/4\n`;
    report += `  - Uppercase: ${hasUpper ? "✅" : "❌"}\n`;
    report += `  - Lowercase: ${hasLower ? "✅" : "❌"}\n`;
    report += `  - Digits: ${hasDigit ? "✅" : "❌"}\n`;
    report += `  - Symbols: ${hasSymbol ? "✅" : "❌"}\n\n`;
    report += `**Overall Strength:** ${strengthLabel} (${score}/6)\n\n`;

    if (triggeredPatterns.length > 0) {
      report += `### ⚠️ Weak Pattern Detected\n\n`;
      triggeredPatterns.forEach((p) => (report += `- ${p}\n`));
      report += "\n";
    }

    report += `### NIST SP 800-63b Recommendations\n\n`;
    if (len < 8) report += `❌ Minimum length is **8 characters** (NIST requirement).\n`;
    if (len < 12) report += `💡 Prefer **12+ characters** for general use.\n`;
    if (len < 16) report += `💡 Use **16+ characters** for high-value accounts.\n`;
    if (classCount < 3) report += `💡 Use a mix of uppercase, lowercase, digits, and symbols.\n`;
    if (entropy < 36) report += `❌ Entropy is critically low — easily brute-forced.\n`;
    if (entropy >= 50) report += `✅ Entropy is sufficient for strong protection.\n`;

    report += `\n### Key NIST Principles\n\n`;
    report += `- ✅ Prioritize **length over complexity**.\n`;
    report += `- ✅ Use a **passphrase** (e.g. 4 random words) for memorability + strength.\n`;
    report += `- ✅ Enable **MFA** — password strength alone is insufficient.\n`;
    report += `- ✅ Check passwords against **breach databases** (e.g. HaveIBeenPwned).\n`;
    report += `- ❌ Do NOT enforce mandatory periodic password changes.\n`;

    return ok(report);
  }
);

// ─────────────────────────────────────────────
// TOOL 7 — generate-threat-report
// Synthesizes findings into a structured threat intelligence report
// ─────────────────────────────────────────────

server.tool(
  "generate-threat-report",
  "Generate a structured threat intelligence report from collected findings. Provide any combination of: domain, IP, hash, CVE IDs, or free-form observations, and get a formatted TI report with risk rating, IOCs, and recommended actions.",
  {
    target: z.string().describe("Primary target being investigated (domain, IP, org name, or system)"),
    domain: z.string().optional().describe("Domain associated with the threat"),
    ip_addresses: z.array(z.string()).optional().describe("IP addresses observed"),
    file_hashes: z.array(z.string()).optional().describe("File hashes (IOCs)"),
    cve_ids: z.array(z.string()).optional().describe("CVE IDs relevant to this threat"),
    observations: z.string().optional().describe("Free-form analyst observations / TTPs observed"),
    threat_actor: z.string().optional().describe("Known or suspected threat actor name (e.g. APT29)"),
    attack_type: z
      .enum(["phishing", "ransomware", "apt", "web-attack", "insider-threat", "supply-chain", "unknown"])
      .default("unknown")
      .describe("Category of the attack"),
    severity: z
      .enum(["critical", "high", "medium", "low"])
      .default("medium")
      .describe("Analyst-assessed severity"),
  },
  async ({
    target,
    domain,
    ip_addresses,
    file_hashes,
    cve_ids,
    observations,
    threat_actor,
    attack_type,
    severity,
  }) => {
    const now = new Date().toISOString().slice(0, 19).replace("T", " ") + " UTC";
    const sevEmoji: Record<string, string> = {
      critical: "🔴",
      high: "🟠",
      medium: "🟡",
      low: "🟢",
    };

    const mitreTactics: Record<string, string[]> = {
      phishing: ["Initial Access (T1566)", "Credential Access (T1539)", "Collection (T1114)"],
      ransomware: ["Execution (T1059)", "Impact (T1486 — Data Encrypted)", "Discovery (T1083)"],
      apt: ["Persistence (T1053)", "Lateral Movement (T1021)", "Exfiltration (T1048)"],
      "web-attack": ["Initial Access (T1190)", "Execution (T1059.007)", "Defense Evasion (T1140)"],
      "insider-threat": ["Collection (T1213)", "Exfiltration (T1567)", "Impact (T1485)"],
      "supply-chain": ["Initial Access (T1195)", "Persistence (T1554)", "Execution (T1072)"],
      unknown: ["Initial Access", "Execution", "Persistence"],
    };

    const tactics = mitreTactics[attack_type] ?? mitreTactics.unknown;

    let report = `# Threat Intelligence Report\n\n`;
    report += `---\n\n`;
    report += `| Field | Value |\n|---|---|\n`;
    report += `| **Report Date** | ${now} |\n`;
    report += `| **Target** | ${target} |\n`;
    report += `| **Attack Type** | ${attack_type.toUpperCase()} |\n`;
    report += `| **Severity** | ${sevEmoji[severity]} ${severity.toUpperCase()} |\n`;
    if (threat_actor) report += `| **Threat Actor** | ${threat_actor} |\n`;
    report += `\n---\n\n`;

    report += `## Executive Summary\n\n`;
    report += `This report documents a **${severity.toUpperCase()}** severity ${attack_type} incident targeting **${target}**. `;
    if (threat_actor) report += `The activity is attributed to or consistent with **${threat_actor}**. `;
    report += `Immediate containment and remediation actions are recommended per the guidelines below.\n\n`;

    report += `## Indicators of Compromise (IOCs)\n\n`;
    if (domain) report += `**Domain:** \`${domain}\`\n`;
    if (ip_addresses?.length) report += `**IP Addresses:**\n${ip_addresses.map((ip) => `- \`${ip}\``).join("\n")}\n`;
    if (file_hashes?.length) report += `**File Hashes:**\n${file_hashes.map((h) => `- \`${h}\``).join("\n")}\n`;
    if (cve_ids?.length) report += `**Exploited CVEs:**\n${cve_ids.map((c) => `- [${c}](https://nvd.nist.gov/vuln/detail/${c})`).join("\n")}\n`;
    report += "\n";

    if (observations) {
      report += `## Analyst Observations\n\n${observations}\n\n`;
    }

    report += `## MITRE ATT&CK Mapping\n\n`;
    report += `Likely tactics/techniques for **${attack_type}** attacks:\n\n`;
    tactics.forEach((t) => (report += `- ${t}\n`));
    report += `\n> Full mapping: https://attack.mitre.org\n\n`;

    report += `## Recommended Actions\n\n`;
    const actions: Record<string, string[]> = {
      phishing: [
        "Block sender domain and IP at email gateway.",
        "Reset credentials for affected users immediately.",
        "Enable MFA on all email accounts.",
        "Conduct user awareness training.",
      ],
      ransomware: [
        "Isolate affected systems from network immediately.",
        "Do NOT pay the ransom — contact law enforcement (FBI IC3).",
        "Restore from clean offline backups.",
        "Patch vulnerable systems and update EDR signatures.",
      ],
      apt: [
        "Initiate full incident response procedure.",
        "Preserve forensic evidence before remediation.",
        "Audit privileged accounts and review AD changes.",
        "Engage a threat hunting team.",
      ],
      "web-attack": [
        "Apply WAF rules to block the attack vector.",
        "Patch the exploited vulnerability immediately.",
        "Review web server access logs for lateral movement.",
        "Rotate any exposed API keys or credentials.",
      ],
      "insider-threat": [
        "Suspend the user account and revoke access tokens.",
        "Preserve audit logs for legal proceedings.",
        "Notify HR and legal teams.",
        "Review DLP alerts for data exfiltration.",
      ],
      "supply-chain": [
        "Audit all third-party software and dependencies.",
        "Verify integrity hashes of software packages.",
        "Apply vendor patches immediately.",
        "Review network traffic for unexpected outbound connections.",
      ],
      unknown: [
        "Isolate affected systems.",
        "Preserve logs and forensic artifacts.",
        "Escalate to security team for full investigation.",
      ],
    };

    const actionList = actions[attack_type] ?? actions.unknown;
    actionList.forEach((a, i) => (report += `${i + 1}. ${a}\n`));
    report += "\n";

    report += `## References & Standards\n\n`;
    report += `- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)\n`;
    report += `- [MITRE ATT&CK Framework](https://attack.mitre.org)\n`;
    report += `- [CISA Advisories](https://www.cisa.gov/uscert/ncas/alerts)\n`;
    if (cve_ids?.length) report += `- [NVD Vulnerability Database](https://nvd.nist.gov)\n`;

    report += `\n---\n*Report generated by CyberSec MCP Server v1.0.0*\n`;

    return ok(report);
  }
);

// ─────────────────────────────────────────────
// MAIN
// ─────────────────────────────────────────────

async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error("🔐 CyberSec MCP Server v1.0.0 running on stdio");
}

main().catch((error) => {
  console.error("Fatal error:", error);
  process.exit(1);
});
