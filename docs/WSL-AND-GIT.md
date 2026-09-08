# WSL setup and git migration

Everything here assumes WSL2 with Ubuntu, the repo cloned under
`/home/ubuntu/projects/`, and the GitHub CLI authenticated as `fa1829`.

Work **inside the WSL filesystem** (`/home/ubuntu/...`), not under `/mnt/c/...`.
Cross-filesystem I/O is slow, and file permissions on `/mnt/c` do not survive,
which silently breaks `chmod 400` on keys.

---

## 1. One-time environment

```bash
sudo apt update
sudo apt install -y python3.12-venv python3-pip git jq

# GitHub CLI, if not already present
type -p gh >/dev/null || {
  sudo mkdir -p -m 755 /etc/apt/keyrings
  wget -qO- https://cli.github.com/packages/githubcli-archive-keyring.gpg \
    | sudo tee /etc/apt/keyrings/githubcli-archive-keyring.gpg >/dev/null
  sudo chmod go+r /etc/apt/keyrings/githubcli-archive-keyring.gpg
  echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/githubcli-archive-keyring.gpg] https://cli.github.com/packages stable main" \
    | sudo tee /etc/apt/sources.list.d/github-cli.list >/dev/null
  sudo apt update && sudo apt install -y gh
}

gh auth status || gh auth login
```

---

## 2. Bring the v2 tree in

```bash
cd ~/projects/cybersec-mcp
git status                     # confirm a clean tree before anything else
git pull --ff-only origin main
```

**Tag v1 before you replace it.** The TypeScript implementation is being removed
from the working tree, and the tag is what makes that reversible.

```bash
git tag -a v1.0.0 -m "v1.0.0 — original 7-tool server (Python + TypeScript)" $(git rev-list -n1 main)
git push origin v1.0.0
```

Work on a branch so the diff is reviewable:

```bash
git checkout -b v2-hardening
```

Copy in the new tree, then remove what v2 replaces:

```bash
# from wherever you unpacked the v2 files
rsync -av --exclude '.git' /path/to/new/cybersec-mcp/ ~/projects/cybersec-mcp/

cd ~/projects/cybersec-mcp
git rm -r --cached src tsconfig.json package.json _test_vt.py _test_analyze.py
rm -rf src tsconfig.json package.json _test_vt.py _test_analyze.py __pycache__
```

`_test_vt.py` and `_test_analyze.py` go because they duplicated `analyze_hash`
inline rather than importing it — the copy could drift from the real code and
still pass. `tests/` replaces them with imports of the actual functions.

---

## 3. Verify before committing

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements-dev.txt

pytest                                                        # 65 passed
ruff check . --select E,F,W,B,S,ASYNC --ignore E501,S101      # All checks passed
python server.py --manifest                                   # digest matches .manifest-digest
pip-audit -r requirements.txt
```

Confirm nothing sensitive is staged. This is the step to actually run, not skim:

```bash
git status
git diff --cached --name-only

# must return nothing
git diff --cached --name-only | grep -E '\.env$|\.pem$|audit\.jsonl|tfstate'
```

If you have ever pasted a real VirusTotal key into a file, check history too:

```bash
git log -p --all -S 'VIRUSTOTAL_API_KEY=' | grep -A1 'VIRUSTOTAL_API_KEY=' | head
```

A key that reached a public commit is compromised even after deletion — rotate
it at VirusTotal rather than trying to rewrite history.

---

## 4. Commit and push

```bash
git add -A
git commit -m "$(cat <<'EOF'
v2.0.0 — security hardening and pipeline layer

Audited v1 against the OWASP MCP Top 10 and fixed what it found.

Security fixes:
- SSRF in scan_headers: v1 fetched any URL with redirects followed and no
  target validation. Reproduced reaching loopback and the 169.254.169.254
  metadata range. All outbound requests now validate scheme, credentials,
  port and every resolved address, and re-validate each redirect hop.
- Indirect prompt injection: VirusTotal, RDAP and header text went straight
  into model context. Now sanitised, fenced and flagged.
- password_strength rated P@ssw0rd123 at 72 bits and called it sufficient
  while flagging it as common. Now leads with guessability; entropy is
  labelled as an upper bound.
- decode_payload accepted invalid base64 and ROT13'd binary garbage. Now
  validates strictly, scores plausibility, recurses to 4 layers, defangs IOCs.
- Error paths returned raw exceptions. Now formatted and secret-redacted.

Added:
- triage_indicator / triage_alert pipeline tools (Suricata EVE ingestion)
- SHA-256 hash-chained audit log with verification
- tool_manifest digest for pinning tool descriptions in CI
- per-host rate limiting and TTL cache sized to free-tier quotas
- 65 tests, ruff, pip-audit, GitHub Actions CI

Removed:
- TypeScript implementation (duplicate of the Python one, undocumented,
  never built). Preserved at tag v1.0.0.
- _test_vt.py / _test_analyze.py: duplicated logic instead of importing it.

Threat model, including residual DNS-rebinding risk: SECURITY.md
EOF
)"

git push -u origin v2-hardening
gh pr create --fill --title "v2.0.0 — security hardening and pipeline layer"
```

Merging your own PR is fine. The point is the reviewable diff, which is worth
having on a repo you will show to interviewers.

```bash
gh pr merge --squash --delete-branch
git checkout main && git pull
git tag -a v2.0.0 -m "v2.0.0 — hardened release" && git push origin v2.0.0
```

---

## 5. Repository hygiene

```bash
gh repo edit --description "Security-tooling MCP server with SSRF guards, prompt-injection containment and a hash-chained audit log"
gh repo edit --homepage "https://faisal-tech.duckdns.org/cybersec-mcp.html"
gh repo edit --add-topic mcp --add-topic cybersecurity --add-topic threat-intelligence \
             --add-topic prompt-injection --add-topic ssrf --add-topic devsecops \
             --add-topic owasp --add-topic python

# Push protection catches a key before it leaves your machine.
gh api -X PATCH repos/fa1829/cybersec-mcp \
  -f security_and_analysis='{"secret_scanning":{"status":"enabled"},"secret_scanning_push_protection":{"status":"enabled"}}'
```

Enable Dependabot with `.github/dependabot.yml`:

```yaml
version: 2
updates:
  - package-ecosystem: pip
    directory: /
    schedule: { interval: weekly }
  - package-ecosystem: github-actions
    directory: /
    schedule: { interval: weekly }
```

---

## 6. Daily use in WSL

```bash
cd ~/projects/cybersec-mcp && source .venv/bin/activate

# manual smoke test without a client
python -c "
import asyncio
from cybersec_mcp.tools import triage_indicator
print(asyncio.run(triage_indicator('CVE-2021-44228')))
"

python server.py --verify-audit
jq 'select(.flags | length > 0)' ~/.cybersec-mcp/audit.jsonl
```

Keys belong in the client config's `env` block or in `.env`, never in a
committed file and never in your shell history:

```bash
# leading space keeps it out of history when HISTCONTROL=ignorespace
 export VIRUSTOTAL_API_KEY='...'
```

---

## Troubleshooting

| Symptom | Cause |
|---|---|
| Client shows no tools, no banner in the MCP log | `command` points at system `python`, not `.venv/bin/python` |
| `ModuleNotFoundError: mcp.server.fastmcp` | `mcp` 2.x installed against a v1-only checkout. v2's shim handles both; re-run `pip install -r requirements.txt` |
| `🚫 Blocked by network policy` on a legitimate internal host | Expected. Only lift it with `CYBERSEC_MCP_ALLOW_PRIVATE_TARGETS=1` on a host with no IMDS and no reachable credentials |
| NVD returns HTTP 403 | Rate limiting, not authorisation. Set `NVD_API_KEY` |
| `audit log unwritable` on stderr | `~/.cybersec-mcp/` not writable, or `CYBERSEC_MCP_AUDIT_PATH` points somewhere the process cannot create |
| Windows-side edits break the venv | Editing under `/mnt/c` from Windows tools. Keep the repo in the WSL filesystem |
