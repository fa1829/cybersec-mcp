# The MCP story — how to tell it

Three audiences, three lengths. Same underlying story: I built a security tool
with a new protocol, audited it against the standard for that protocol, found my
own bug, and fixed it in the open.

That shape is the asset. Anyone can post a repo. Far fewer can point at a
vulnerability they found in their own work and explain what they changed.

---

## Why MCP matters to a security engineer

The [Claude Academy course](https://academy.claude.com/courses/introduction-to-model-context-protocol/introducing-mcp)
frames MCP as a way to shift the burden of tool definitions and execution away
from your application onto specialised servers. Instead of hand-writing a tool
schema for every GitHub endpoint, you connect to a GitHub MCP server that has
already done it.

That framing is correct, and for a security engineer it has a second edge.

**The integration burden moves — and so does the trust boundary.** "Someone else
already implemented the tools" also means someone else's code now runs inside
your agent's decision loop. Before MCP, an agent had a small fixed set of tools
compiled into the application. With MCP it discovers tools at runtime from any
server it can reach, and every one of those servers is a trust boundary that did
not exist in your threat model last year.

Four things follow, and they are what I would say in an interview:

**1. The tool description is executable.** In conventional software the caller is
code you control. In MCP the caller is a model reading your docstring. Change the
prose and you change runtime behaviour with no logic change anywhere. That is why
OWASP's MCP Top 10 has an entire category for tool poisoning, and why my server
publishes a manifest digest that CI pins.

**2. Tool output is an injection channel.** Tool descriptions get reviewed once,
when the client connects. Tool *responses* reach the model on every call with no
equivalent check. A VirusTotal file name is submitter-controlled. A WHOIS
registrant field is registrant-controlled. An HTTP header is set by the site
you are scanning. All of it lands in the model's context wearing the server's
voice. My server fences it, labels it as evidence rather than instructions, and
flags likely injection attempts in the audit log.

**3. Autonomous tool calls need an audit trail, or they never happened.** OWASP
lists lack of audit and telemetry as its own MCP risk. When a model decides to
call a tool, an unlogged call is an action nobody can reconstruct afterwards.

**4. The adoption curve outran the security curve.** Testing in 2026 found 36.7%
of over 7,000 public MCP servers vulnerable to SSRF, 43% to command injection,
and more than 30 CVEs filed against MCP tooling in January and February alone —
including a CVSS 9.4 RCE in Anthropic's own MCP Inspector. Mine was in the SSRF
bucket until I checked. That is not an indictment of the protocol; it is what
every fast-adopted protocol looks like at this stage, and it is exactly the gap
security engineers get hired to close.

The honest summary: MCP is the integration layer AI agents needed, and it
arrived without the security practice around it. Knowing both halves is a
narrow and currently valuable skill.

---

## LinkedIn post

Tag Nicandro if he is comfortable with it — the project came from his advice, and
crediting the conversation is both accurate and good practice.

> A few months ago a Bell engineer gave me some advice: automate a security log
> and event correlation pipeline using Python, MCP and GenAI. I built it. Then I
> attacked it, and found my own bug.
>
> **What I built.** cybersec-mcp — a Model Context Protocol server giving an AI
> assistant eleven security tools: indicator triage, CVE lookup with CVSS
> exploitability, HTTP header auditing, domain OSINT, recursive payload decoding,
> NIST 800-63B password assessment. Suricata alert in, enriched dossier out.
>
> **What I found.** Auditing v1 against the OWASP MCP Top 10, my
> `scan_headers` tool fetched any URL it was handed, followed redirects
> automatically, and validated nothing. I reproduced it reaching
> `169.254.169.254` — the cloud instance-metadata endpoint. On an EC2 host
> running IMDSv1 that returns the instance role's temporary AWS credentials. It
> is the mechanism behind the Capital One breach, and my server was deployed on
> EC2.
>
> Independent testing in 2026 found 36.7% of over 7,000 public MCP servers with
> the same class of flaw. Mine was one of them.
>
> **What I changed.** Every outbound request now validates scheme, credentials,
> port and every resolved address, and re-validates each redirect hop —
> "validate the first URL, then follow a 302 to the metadata endpoint" is the
> standard bypass. Third-party API text is fenced and injection-flagged before it
> reaches the model. Every tool call appends to a SHA-256 hash-chained audit log.
> A manifest digest pins every tool description in CI, because in MCP a docstring
> is an instruction the model acts on — changing one changes agent behaviour with
> no code change anywhere.
>
> **What I did not fix.** DNS rebinding is still open. Closing it needs address
> pinning at the socket layer. It is written up in the threat model rather than
> quietly omitted, because a security document that claims total coverage is not
> a security document.
>
> The thing I did not expect to learn: in MCP, prose is production code. The
> docstring is the interface. That took some getting used to coming from
> 16 years in telecom networks.
>
> Code, threat model and the full audit write-up:
> github.com/fa1829/cybersec-mcp
>
> Thanks Nicandro — the pipeline layer is a direct answer to what you suggested.
>
> #cybersecurity #MCP #AIsecurity #OWASP #DevSecOps #ThreatIntelligence

**Post it with the SSRF before/after as the image.** The two code blocks side by
side — v1 returning HTTP 200 from the metadata range, v2 returning the block with
its reason. That is the whole story in one screenshot.

---

## Resume entry

> **cybersec-mcp** — Model Context Protocol server exposing 11 security tools
> (threat-intel enrichment, CVE/CVSS lookup, HTTP header auditing, domain OSINT,
> payload analysis) to AI assistants. Audited the initial release against the
> OWASP MCP Top 10, identified and reproduced an SSRF permitting access to cloud
> instance metadata, and remediated with address-level target validation and
> per-hop redirect re-validation. Added indirect-prompt-injection containment for
> third-party API responses, a SHA-256 hash-chained audit log, tool-manifest
> integrity pinning enforced in CI, and quota-aware rate limiting. 65 tests,
> GitHub Actions, deployed on AWS EC2 with Terraform.

---

## Interview talking points

### "Walk me through a project you're proud of."

Lead with the bug, not the feature list. The feature list is what everyone else
opens with.

> I built an MCP server that gives an AI assistant security tools. The part worth
> talking about is that I then audited it against OWASP's MCP Top 10 and found
> SSRF in my own code. One tool fetched arbitrary URLs with redirects followed
> and no validation — I reproduced it reaching the cloud metadata endpoint, on
> the same EC2 box that serves my portfolio site. Same class of flaw as Capital
> One. So I rebuilt the network layer: one function all outbound traffic goes
> through, validating scheme, port and every resolved address, re-validating each
> redirect hop. Then I wrote up what I *didn't* fix — DNS rebinding is still
> open, and it's in the threat model.

### "How do you handle prompt injection?"

> Layered, and I'd say up front that no layer is complete. Structurally: all
> third-party text gets stripped of control and zero-width characters,
> neutralised so it can't escape its fence, and wrapped in a labelled block
> telling the model this is evidence to report, not instructions to follow.
> Heuristically: nine patterns for instruction overrides, role reassignment,
> chat-template tokens, exfiltration directives — that's a tripwire, not a
> filter, and it'll miss novel phrasings. Operationally: hits get flagged in the
> audit log so they're reviewable. The fencing is the actual control. The pattern
> list is detection.

### "What would you do differently?"

> Threat-model before writing code. I built seven tools, then audited, then
> rebuilt the network layer. If I'd asked "what's the worst thing this tool could
> be told to fetch?" on day one, `scan_headers` would have had the guard from the
> first commit. It cost me a rewrite. The upside is that I now have a
> before-and-after I can actually show, which a clean first draft would not have
> given me.

### "How do you keep an MCP server maintainable as tools change?"

This is the question that shows the transferable skill.

> Three things. One file per tool, so adding one touches an import and a list.
> A control plane every tool routes through — the SSRF guard and rate limiter are
> in the HTTP client, so a new tool gets them by using the shared fetch function
> rather than by remembering to. And a manifest digest pinned in CI: descriptions
> are instructions the model acts on, so changing one is a behavioural change and
> should fail the build until someone acknowledges it. I've written that process
> up in the repo as a guide for adding, modifying and removing tools.

### "You come from telecom. Why security?"

> Sixteen years of RF planning and optimisation is mostly the same discipline
> under a different name: you're reasoning about a system that adversaries and
> physics both interfere with, and you're building evidence for decisions when
> the data is incomplete. My thesis was reinforcement-learning DDoS mitigation in
> Open RAN, which sits directly on both. The MCP work is the newest layer — same
> instinct, applied to a protocol that's twelve months old and moving fast.

---

## Things to avoid saying

- **"Production-ready" or "enterprise-grade."** It is a personal project with a
  documented open vulnerability. The honesty is what makes it credible; a
  marketing word undoes that in one syllable.
- **"Secure."** Say what it defends against and what it does not. That is what
  the threat model is for, and it is the vocabulary a security team uses.
- **Overstating the AI part.** You built a server exposing tools over a protocol.
  You did not build a model. Being precise about that is a positive signal.
- **Hiding the DNS rebinding gap.** If an interviewer finds it themselves, it
  reads as an oversight. If you raise it, it reads as threat modelling. It is the
  same fact — the difference is entirely in who says it first.
