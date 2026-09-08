# Adding, changing and removing tools

This is the part that transfers to a real organisation. The specific tools here
are a portfolio; the change process is the skill.

---

## The mental model

An MCP tool is four things:

```
async def my_tool(param: str, flag: bool = False) -> str:
    """First line becomes the summary the model reads.

    The rest of the docstring tells the model when to use this and what
    it gets back. This text is production code.

    Args:
        param: what this is, in terms the model can act on.
        flag: what changes when it is true, and the default's reasoning.
    """
    return "markdown"
```

| Client sees | Comes from | Change control |
|---|---|---|
| name | function name | breaking — clients may reference it |
| description | docstring | **behavioural** — changes what the agent does |
| parameters | signature + type hints | breaking if you rename or narrow |
| result | returned string | free to change |

The uncomfortable one is the second row. In normal software the caller is code
you control. In MCP the caller is a model reading your docstring, so prose is a
runtime input. That is why the OWASP MCP Top 10 has a whole category for tool
poisoning, and why this repo pins a manifest digest.

---

## Adding a tool

Worked example: an EPSS lookup — the probability a CVE will be exploited in the
next 30 days. It pairs naturally with `check_cve`, which already tells you the
severity but not the likelihood.

### 1. Write the logic, no MCP

`cybersec_mcp/tools/epss.py`:

```python
"""EPSS — exploit prediction scoring, from FIRST."""

from __future__ import annotations

from ..httpclient import cache_get, cache_put, describe_error, fetch
from .cve import CVE_RE


async def check_epss(cve_id: str) -> str:
    """Get a CVE's EPSS score: the probability it will be exploited in 30 days.

    Use this alongside check_cve. CVSS says how bad a vulnerability is if
    exploited; EPSS says how likely exploitation actually is. A CVSS 9.8 with
    an EPSS of 0.001 is usually a lower priority than a CVSS 6.5 at 0.7.

    Args:
        cve_id: CVE identifier such as CVE-2021-44228.
    """
    cid = cve_id.strip().upper()
    if not CVE_RE.match(cid):
        return f"❌ `{cid[:40]}` is not a valid CVE ID."

    key = f"epss:{cid}"
    if (hit := cache_get(key)):
        return hit + "\n> 🗃️ Served from local cache.\n"

    try:
        response, _ = await fetch(f"https://api.first.org/data/v1/epss?cve={cid}")
    except Exception as exc:  # noqa: BLE001
        return describe_error(exc)

    if response.status_code != 200:
        return f"⚠️ EPSS API returned HTTP {response.status_code}."

    rows = response.json().get("data", [])
    if not rows:
        return f"## {cid}\n\nNo EPSS score published. Scores appear a few days after publication.\n"

    score = float(rows[0].get("epss", 0))
    percentile = float(rows[0].get("percentile", 0))

    out = f"## {cid} — EPSS\n\n| Field | Value |\n|---|---|\n"
    out += f"| Exploitation probability (30d) | {score:.1%} |\n"
    out += f"| Percentile | {percentile:.1%} of all scored CVEs |\n\n"
    if percentile > 0.95:
        out += "> 🔴 Top 5% by exploitation likelihood. Patch ahead of higher-CVSS items with lower EPSS.\n"
    elif score < 0.01:
        out += "> 🟢 Under 1%. Real but low — schedule it rather than escalating.\n"
    out += "\n> EPSS predicts exploitation *in the wild*, not whether **you** are exposed. Reachability still decides.\n"

    cache_put(key, out)
    return out
```

Four things that are not optional, and are the same in any codebase with a
control plane:

- **Use `fetch`, never `httpx` directly.** Bypassing it bypasses the SSRF guard,
  the rate limiter and the cache. That single import is what makes the guard a
  guarantee rather than a convention.
- **Return errors, never raise them.** An exception reaching the model becomes a
  traceback in its context. `describe_error` formats and redacts.
- **Sanitise anything the third party controls.** This response is numeric so it
  is fine as-is. If it returned free text, it would go through `sanitize()`.
- **Say what the tool does not tell you.** The closing caveat is what stops a
  model presenting a probability as a verdict.

### 2. Export it

```python
# cybersec_mcp/tools/__init__.py
from .epss import check_epss
__all__ = [..., "check_epss"]
```

### 3. Register it

```python
# server.py
from cybersec_mcp.tools import ..., check_epss

TOOLS = [
    triage_indicator,
    triage_alert,
    analyze_hash,
    check_cve,
    check_epss,        # ← near check_cve; order is a hint to the model
    ...
]
```

That is all. The `audited` wrapper, the manifest and the audit log pick it up
automatically because they iterate `TOOLS`.

### 4. Wire it into the pipeline, if it belongs there

```python
# cybersec_mcp/tools/triage.py
elif kind == "cve":
    tasks.append(group.create_task(check_cve(value)))
    tasks.append(group.create_task(check_epss(value)))   # runs concurrently
```

Ask before doing this: does the extra call earn its cost on **every** triage?
Each addition spends latency, API quota and context window. Tools that are
occasionally useful stay standalone.

### 5. Test it

```python
# tests/test_tools.py
def test_epss_rejects_bad_ids():
    import asyncio
    from cybersec_mcp.tools.epss import check_epss
    assert "not a valid CVE" in asyncio.run(check_epss("not-a-cve"))

def test_epss_is_in_the_manifest():
    from server import TOOLS
    assert any(t.__name__ == "check_epss" for t in TOOLS)
```

Test the offline paths — validation, formatting, thresholds. Do not test the
live API; that makes CI depend on FIRST's uptime.

### 6. Update the pin

```bash
pytest
python server.py --manifest
python server.py --manifest | grep -oE '[0-9a-f]{64}' | head -1 > .manifest-digest
git add -A && git commit -m "feat: add check_epss for exploitation likelihood

Pairs with check_cve: CVSS gives severity, EPSS gives likelihood.
Manifest digest updated — one tool added, no existing descriptions changed."
```

CI compares the digest to the file. Updating it **in the same commit, with the
reason in the message**, is the whole control. A digest bump with no explanation
is the thing to catch in review.

---

## Modifying a tool

Three tiers, escalating in blast radius.

### Tier 1 — output only

Changing the returned Markdown. Safe. The digest does not move (results are not
part of the manifest), and no client behaviour changes.

### Tier 2 — description

**This changes agent behaviour with no logic change.** Sharpening
`scan_headers`'s docstring to mention "only public targets" makes the model stop
attempting internal hosts before the guard ever fires — a real improvement, made
entirely in prose.

The digest moves. Review it like a code change, because it is one. In an
organisation this is where the control lives: a PR that touches only docstrings
still needs review, and CI failing on the digest is what forces that PR to exist.

### Tier 3 — signature

Adding, renaming or retyping a parameter. Breaking. Add optional parameters with
defaults; do not rename existing ones.

```python
# safe — old calls still work
async def scan_headers(url: str, follow_redirects: bool = True) -> str:

# breaking — every existing call fails
async def scan_headers(target_url: str) -> str:
```

If you must rename, keep the old name as an alias for a release:

```python
async def analyze_hash(file_hash: str = "", hash: str = "") -> str:
    """...

    Args:
        file_hash: Hex file hash.
        hash: Deprecated alias for file_hash. Will be removed in 3.0.
    """
    value = file_hash or hash
```

That is exactly the migration this repo made in v2 — `hash` shadowed a Python
builtin — except v1 had no external users, so it was renamed outright. In a real
org with consumers you cannot do that, and the alias is the cost of the fix.

---

## Removing a tool

```bash
git rm cybersec_mcp/tools/passwords.py
# remove from tools/__init__.py, from TOOLS in server.py, from tests, from README
pytest
python server.py --manifest | grep -oE '[0-9a-f]{64}' | head -1 > .manifest-digest
```

Removal is the loudest change. The digest moves, the tool count in the banner
drops, and any client config or saved prompt referencing it breaks. Deprecate
first where you can:

```python
async def old_tool(x: str) -> str:
    """DEPRECATED — use triage_indicator instead. Removed in 3.0.
    ...
    """
    return "⚠️ Deprecated. Use `triage_indicator`.\n\n" + await triage_indicator(x)
```

The docstring is where the deprecation goes, because that is what the model
reads. A deprecation warning in a log the model never sees does nothing.

---

## Adding a new external API

Ten-minute checklist before you write the tool:

1. **Rate limit?** Add the host to `RATE_LIMITS` in `config.py` at or under the
   documented free-tier ceiling.
2. **Authenticated?** Key in `config.py` alongside the others so `SECRETS`
   redaction covers it. Never a literal, never a default value.
3. **Does it return attacker-influenceable text?** Almost always yes — anything
   user-submitted, registrant-supplied or scraped. Route it through `sanitize()`.
4. **Cacheable?** Static data (CVE records, WHOIS) yes. Live status no.
5. **What is its rate-limit response?** NVD uses 403, VirusTotal uses 429.
   Explain it rather than surfacing a bare code — that one detail saves your
   future self an hour.
6. **What does the query disclose?** Every lookup tells that service what you are
   investigating. That is why `triage_alert` withholds RFC1918 addresses.
7. **Graceful without a key?** The tool should still do its offline half and say
   plainly that enrichment was skipped.

---

## Triage guide when a tool misbehaves

Work down. Each step eliminates a layer.

```
1. Call the function directly in Python.
   Fails → your logic. Stop here.

2. Run the stdio harness (docs/LOCAL-TESTING.md stage 5a).
   Tool missing → not in TOOLS, or an import error. Check stderr.
   Present but errors → the audited wrapper, or a schema mismatch.

3. Open MCP Inspector, read the description and schema.
   Wrong types → check type hints; the SDK derives the schema from them.
   Confusing description → this is why the model calls it wrongly.

4. Check the client's MCP log.
   No banner → the process never started. Interpreter path.
   Started then dropped → something wrote to stdout.

5. Check the audit log.
   No record → never reached your code.
   outcome=error → read `detail`.
   flags=[ssrf-blocked] → policy did its job.

6. Compare the manifest digest against .manifest-digest.
   Moved unexpectedly → someone changed a description. That is your bug.
```

Steps 3 and 6 have no equivalent in conventional debugging, and they are where
MCP-specific problems live. Everything else is ordinary subprocess work.
