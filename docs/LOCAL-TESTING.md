# Local testing runbook

Nine stages, in order. Each one has **Do this**, then **What you just learned** —
the concept behind the step, so that when a tool needs adding, changing or
removing in a real environment you know which layer to look at.

Budget about 45 minutes the first time.

---

## Stage 0 — File organisation

Everything lives in the WSL filesystem. Not `/mnt/c`.

```
/home/ubuntu/projects/
├── cybersec-mcp/                  ← this repo
│   ├── .venv/                     ← git-ignored, per-project
│   ├── .env                       ← git-ignored, real keys
│   ├── .env.example               ← committed, empty template
│   ├── .manifest-digest           ← committed, pinned by CI
│   ├── server.py                  ← entrypoint only
│   ├── cybersec_mcp/              ← the package
│   │   ├── config.py              ← every env var, one place
│   │   ├── safety.py              ← SSRF guard, sanitiser, redaction
│   │   ├── httpclient.py          ← the only outbound path
│   │   ├── audit.py               ← hash-chained log
│   │   ├── integrity.py           ← manifest digest
│   │   └── tools/                 ← one file per tool
│   ├── tests/
│   └── docs/
└── aws-dual-host-project/         ← website + Terraform (separate repo)
    └── website/                   ← where cybersec-mcp.html goes
```

Outside the repo:

```
~/.cybersec-mcp/audit.jsonl        ← runtime audit log, never committed
~/.ssh/faisal-key.pem              ← chmod 400
```

**What you just learned.** Three separations that matter in any MCP project:

- **Entrypoint vs logic.** `server.py` only registers and runs. All behaviour is
  importable without starting a server, which is why the tests need no transport.
- **Config in one file.** Every environment variable is declared in `config.py`.
  When someone asks "what can we tune in production?", that file is the answer.
  Scattered `os.environ.get()` calls are how servers acquire undocumented knobs.
- **Runtime state outside the repo.** The audit log lives in `~`, not the working
  tree. A log file inside a git repo eventually gets committed.

---

## Stage 1 — Environment

```bash
cd ~/projects/cybersec-mcp

python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements-dev.txt

python -c "import mcp, httpx; print('mcp', mcp.__version__ if hasattr(mcp,'__version__') else 'ok'); print('httpx', httpx.__version__)"
```

**What you just learned.** The venv is not optional housekeeping. An MCP client
launches your server as a subprocess with an absolute path to a Python
interpreter. If that interpreter is the system one, `mcp` will not be importable
and the server dies before it speaks a word of protocol — the single most common
"my server doesn't show up" cause.

Note the exact path now, you need it in Stage 6:

```bash
echo $(pwd)/.venv/bin/python
```

---

## Stage 2 — Tests and lint

```bash
pytest                                                     # expect: 65 passed
ruff check . --select E,F,W,B,S,ASYNC --ignore E501,S101   # expect: All checks passed!
```

Then break something on purpose and watch it fail:

```bash
# temporarily allow private targets
CYBERSEC_MCP_ALLOW_PRIVATE_TARGETS=1 pytest tests/test_safety.py -k internal
```

Seven of those should fail — the loopback and RFC1918 cases. The three cloud
metadata cases keep passing, because that block is unconditional and the
override does not reach it.

This is the point of the drill. Config genuinely changes behaviour, so the test
proves the guard is doing the work rather than the URL happening to be
unreachable — and it shows you exactly how far the escape hatch reaches.

**What you just learned.** The tests are offline by design — no network, no API
keys. That is what makes them runnable in CI and on a plane. When you add a tool
that talks to a new API, split it the same way: pure logic (parsing,
classification, formatting) gets unit tests; the network call gets a manual
check. If a function needs the internet to be tested, it is usually doing two
jobs and should be two functions.

---

## Stage 3 — Call the tools directly, no MCP involved

```bash
python - <<'EOF'
import asyncio
from cybersec_mcp.tools import decode_payload, password_strength, generate_threat_report

async def main():
    print(await decode_payload("cG93ZXJzaGVsbCAtZW5jIGFHVnNiRzhnZDI5eWJHUT0="))
    print(await password_strength("Summer2026!"))

asyncio.run(main())
EOF
```

Check three things in the output:

1. The decoder reports **one layer** plus an **Embedded encoded blobs** section.
   One layer is correct here: only the outer string is wholly base64. The inner
   blob is an *argument* inside a command line, which is the shape of every real
   `powershell -enc` payload, so it is decoded separately rather than as a layer.
2. It flags **PowerShell execution**, **remote payload retrieval** and **shell
   download-and-run**, and the extracted URL comes out defanged.
3. `Summer2026!` comes back **trivially guessable**, and the entropy figure is
   labelled as an upper bound rather than presented as strength.

**What you just learned.** Tools are plain async functions returning Markdown.
No MCP decorator, no transport, no client. This is the debugging move that saves
the most time in a real environment: when a tool misbehaves through the client,
call the function directly first. If it fails here, it is your logic. If it works
here but fails through the client, it is registration, schema or environment —
a completely different search space.

---

## Stage 4 — Prove the SSRF guard, then prove it can be turned off

```bash
python - <<'EOF'
import asyncio
from cybersec_mcp.tools import scan_headers

targets = [
    "http://169.254.169.254/latest/meta-data/",   # cloud metadata
    "http://127.0.0.1:8080/",                     # loopback
    "http://192.168.1.1/",                        # RFC1918
    "file:///etc/passwd",                         # wrong scheme
    "https://example.com:6379/",                  # redis port
    "https://user:pass@example.com/",             # embedded creds
    "https://example.com/",                       # should succeed
]
async def main():
    for t in targets:
        out = await scan_headers(t)
        first = [l for l in out.splitlines() if l.strip()][-1]
        print(f"{t:45s} → {first[:95]}")
asyncio.run(main())
EOF
```

Six blocks with specific reasons, one success. Now watch the guard come off:

```bash
CYBERSEC_MCP_ALLOW_PRIVATE_TARGETS=1 python -c "
import asyncio
from cybersec_mcp.tools import scan_headers
print(asyncio.run(scan_headers('http://127.0.0.1:8080/'))[:200])
"
```

**What you just learned.** Two things worth carrying into any organisation.

First: **a security control you cannot demonstrate is a claim, not a control.**
Being able to run this list in front of a reviewer is the difference between "we
handle SSRF" and showing six specific rejections with reasons.

Second: **every control needs an escape hatch, and the escape hatch is a risk.**
`CYBERSEC_MCP_ALLOW_PRIVATE_TARGETS` exists because scanning internal hosts is a
legitimate need on an isolated lab box. It defaults to off, it is documented as
dangerous, and the startup banner prints its state so nobody discovers it was on
by accident. When you add a bypass in production, do all three.

---

## Stage 5 — The MCP protocol layer

Now test through actual MCP, still without a chat client.

### 5a. Your own harness

```bash
cat > /tmp/harness.py <<'EOF'
import asyncio, os, sys, json
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

async def main():
    params = StdioServerParameters(
        command=sys.executable, args=["server.py"],
        env={**os.environ}, cwd=os.getcwd())
    async with stdio_client(params) as (r, w):
        async with ClientSession(r, w) as s:
            await s.initialize()
            tools = await s.list_tools()
            print(f"{len(tools.tools)} tools\n")
            for t in tools.tools:
                args = list((t.inputSchema or {}).get("properties", {}))
                print(f"  {t.name:26s} {args}")
            print()
            res = await s.call_tool("triage_indicator", {"indicator": "CVE-2021-44228"})
            print("".join(c.text for c in res.content if getattr(c, "text", None))[:900])

asyncio.run(main())
EOF
python /tmp/harness.py
```

Expect 11 tools, with `triage_indicator` first.

### 5b. MCP Inspector — the tool the Academy course uses

```bash
# pin the version: CVE-2025-49596 was a CVSS 9.4 RCE in Inspector before 0.14.1
npx @modelcontextprotocol/inspector@latest \
  $(pwd)/.venv/bin/python $(pwd)/server.py
```

Opens a browser UI. Click through **Tools** and check each one's description and
schema — this is exactly what the model sees. Call `tool_manifest` from the UI.

**What you just learned.** The MCP contract is four things and nothing more:

| The client sees | Comes from |
|---|---|
| Tool name | the Python function name |
| Tool description | the function's **docstring** |
| Parameter names and types | the function **signature** and type hints |
| Result | the returned string |

That is the whole interface. It also means something people find surprising the
first time: **the docstring is production code.** It is not a comment — it is the
instruction the model reads when deciding whether and how to call your tool. Edit
a docstring and you have changed runtime behaviour without touching a line of
logic. This is why `tool_manifest` exists, and why the OWASP MCP Top 10 lists
tool poisoning as its own risk category.

Notice too that the SSRF guard, the sanitiser and the audit log are invisible
here. A client can only see names, descriptions and schemas. It cannot tell a
hardened server from an unhardened one — which is why "treat every MCP server as
untrusted" is the standing advice.

---

## Stage 6 — Wire it into a real client

Take the path from Stage 1.

**Claude Desktop on Windows** — `%APPDATA%\Claude\claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "cybersec-mcp": {
      "command": "wsl.exe",
      "args": [
        "-d", "Ubuntu", "--",
        "/home/ubuntu/projects/cybersec-mcp/.venv/bin/python",
        "/home/ubuntu/projects/cybersec-mcp/server.py"
      ],
      "env": { "VIRUSTOTAL_API_KEY": "", "NVD_API_KEY": "" }
    }
  }
}
```

**IBM Bob inside WSL** — `.bob/mcp.json`, no `wsl.exe` wrapper needed:

```json
{
  "mcpServers": {
    "cybersec-mcp": {
      "command": "/home/ubuntu/projects/cybersec-mcp/.venv/bin/python",
      "args": ["/home/ubuntu/projects/cybersec-mcp/server.py"],
      "env": { "VIRUSTOTAL_API_KEY": "" }
    }
  }
}
```

Restart the client fully — not just the window. Then ask it:

```
What MCP tools do you have available?
Triage this indicator: 44d88612fea8a8f36de82e1278abb02f
Audit the security headers on https://faisal-tech.duckdns.org
What is the tool manifest digest?
```

**What you just learned.** The client launches your server as a subprocess and
speaks JSON-RPC over stdin/stdout. Three consequences that explain most
first-time failures:

- **Never `print()` to stdout.** stdout *is* the protocol channel. A stray print
  corrupts the JSON-RPC stream and the client drops the connection with an
  unhelpful error. All diagnostics go to stderr — that is why the startup banner
  uses `file=sys.stderr`.
- **The subprocess does not inherit your shell.** No `.bashrc`, no `.env`, no
  `PATH` you set. Anything the server needs comes from the `env` block or from
  absolute paths.
- **The config is on the client's side of the boundary.** With Claude Desktop on
  Windows and the server in WSL, the config is Windows-side and the paths are
  Linux-side. That mismatch is the WSL-specific gotcha.

---

## Stage 7 — Audit log

```bash
cat ~/.cybersec-mcp/audit.jsonl | jq -c '{ts, tool, outcome, flags}' | tail -10

python server.py --verify-audit          # ✅ Chain intact across N record(s)

jq 'select(.flags[]? == "ssrf-blocked")'        ~/.cybersec-mcp/audit.jsonl
jq 'select(.flags[]? == "possible-injection")'  ~/.cybersec-mcp/audit.jsonl

# confirm passwords are absent
grep -c 'Summer2026' ~/.cybersec-mcp/audit.jsonl     # expect 0
```

Now tamper with it and watch verification catch you:

```bash
cp ~/.cybersec-mcp/audit.jsonl /tmp/backup.jsonl
sed -i '2s/"outcome": "ok"/"outcome": "tampered"/' ~/.cybersec-mcp/audit.jsonl
python server.py --verify-audit          # 🔴 Line 2: entry_hash mismatch
cp /tmp/backup.jsonl ~/.cybersec-mcp/audit.jsonl
```

**What you just learned.** When an agent calls tools on its own initiative, the
audit log is the only reconstruction of what happened. Two design points that
generalise:

- **Redact at write time, not read time.** The password never enters the record.
  A log you have to sanitise before sharing is a log nobody shares.
- **Chaining makes edits visible, not impossible.** Anyone who can write the file
  can recompute the chain. Say that out loud rather than overselling it — in a
  real deployment you ship to append-only storage (CloudWatch Logs with a
  retention policy, or an S3 bucket with object lock) and the chain becomes
  evidence that shipping worked.

---

## Stage 8 — Failure drills

Deliberately break things so you recognise the symptoms later.

```bash
# 1. wrong interpreter — the #1 "no tools appear" cause
/usr/bin/python3 server.py          # ModuleNotFoundError: No module named 'mcp'

# 2. stdout pollution — the #2 cause
python -c "
import sys
sys.argv=['server.py']
print('this breaks the protocol')   # goes to stdout
exec(open('server.py').read())
" 2>/dev/null | head -3

# 3. unwritable audit path
CYBERSEC_MCP_AUDIT_PATH=/root/nope/audit.jsonl python server.py --manifest
# warns on stderr, does not crash

# 4. rate limit
python -c "
import asyncio
from cybersec_mcp.tools import check_cve
async def m():
    for i in range(12):
        r = await check_cve('CVE-2021-44228')
        print(i, 'cache' if 'cache' in r else ('limited' if '⏳' in r else 'live'))
asyncio.run(m())
"
```

**What you just learned.** The failure modes worth memorising:

| Symptom | Layer | First check |
|---|---|---|
| No tools appear, no banner in the client log | process | interpreter path |
| Client connects then immediately drops | protocol | something wrote to stdout |
| Tool visible but never called | schema/description | is the docstring clear about when to use it? |
| Tool called with wrong arguments | schema | type hints and `Args:` block |
| Works standalone, fails in client | environment | `env` block, absolute paths |
| `🚫 Blocked by network policy` | policy | working as designed — check before overriding |
| HTTP 403 from NVD | quota | rate limit, not authorisation. Set `NVD_API_KEY` |

Note where "tool visible but never called" sits. In conventional software you
debug the call site; in MCP the model *is* the call site, and you debug it by
rewriting a docstring. That takes getting used to.

---

## Stage 9 — Pre-commit gate

```bash
pytest && ruff check . --select E,F,W,B,S,ASYNC --ignore E501,S101
python server.py --manifest | grep -oE '[0-9a-f]{64}' | head -1
cat .manifest-digest        # must match the line above

git status
git diff --cached --name-only | grep -E '\.env$|\.pem$|audit\.jsonl' && echo "STOP" || echo "clean"

pip-audit -r requirements.txt
```

**What you just learned.** The manifest check is the unusual one, and it is the
one worth explaining in an interview. Everything else in the gate is standard
engineering hygiene. The manifest digest exists because in MCP, editing a
docstring changes what the agent does — so the description set gets the same
change control as a dependency version. If the digest moves and you did not
intend it, something changed the model's instructions.
