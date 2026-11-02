# Moraa — Webhook Security (inbound receivers + outbound senders)

> Written after a real engagement: two in-scope hosts (`webhooks.blobstore.svc`,
> `billing-stripe-webhook.svc`) were signature-gated API Gateway endpoints with NO enumeration
> oracle — no route fuzzing, no 404-vs-403 tell — and the library had no methodology for them.
> This doc covers BOTH directions: attacking a webhook RECEIVER (inbound) and abusing an app's
> OUTBOUND webhook delivery as a primitive. Cross-ref [[ssrf]] (the outbound side is an SSRF
> subclass), [[request-signing]] (signature-gating is the same mechanism, provider-side),
> [[business-logic]] (forged events are business-logic injection), [[controls-and-oracles]] (the
> no-route-oracle problem is a ceiling you must state, not guess through).

## The shape of the surface

```
PROVIDER (Stripe/GitHub/storage-svc…)  ──signed POST──▶  RECEIVER (your target)
   the target ALSO plays provider:      ──signed POST──▶  YOUR URL (outbound direction)
```
Two rules before anything: receivers authenticate by SIGNATURE, not by session — your normal
authenticated-session tricks don't apply; and a receiver with no route oracle (every path returns
the same generic response) cannot be blind-fuzzed safely or meaningfully — see §2 for what to do
instead.

## 1. INBOUND — attacking a webhook receiver

### 1a. Does it verify the signature AT ALL?

```bash
# provider event format is public knowledge for known providers (Stripe: JSON + "Stripe-Signature"
# header; generic: JSON body + X-Signature/X-Hub-Signature). Replaying a REAL captured event
# (one your own tenant triggered) with modifications is the test — never a fabricated schema:
EV='<paste the captured, real event JSON from your own delivery log>'
# baseline: unmodified replay → expect whatever "processed/duplicate" looks like
curl -s -D - -X POST "https://webhooks.blobstore.svc/provider" -H 'Content-Type: application/json' \
     -d "$EV" | head -20
# THE TEST: same replay, one field flipped (amount, status, target id)
curl -s -o /dev/null -w '%{http_code}\n' -X POST "https://webhooks.blobstore.svc/provider" \
     -H 'Content-Type: application/json' \
     -d "$(echo "$EV" | sed 's/"status":"paid"/"status":"refunded"/')"
```
If a modified body is processed the same way a signed one is (or you get a *different*
state-changing response vs. the bad-signature baseline), the check is missing or non-functional.
Compare against a definitely-bad signature to see what "rejected" looks like —
[[controls-and-oracles]] discipline: know both readings before trusting either.

### 1b. Weak / non-timing-safe comparison

If the receiver compares the submitted signature to its computed HMAC with `==` (or a language
default), the comparison is not constant-time. Timing attacks on HMAC-compare over a network are
extremely hard to land and almost never a standalone bug-bounty finding — note the code-level
observation if source is available, but don't burn engagement time trying to prove a byte-by-byte
timing differential over the internet. The honest claim available to you: "signature compared via
non-constant-time equality (visible in error behaviour/source)" — a note, not a finding.

### 1c. Algorithm / scheme confusion

```bash
# many receivers parse "v1=<hex>,t=<ts>" or "sha256=<hex>" loosely. Probe the parser with
# SCHEME VARIANTS of a captured signature — some implementations dispatch on a prefix you control:
-H 'X-Signature: sha1=<captured-hex>'          # downgrade the digest name
-H 'X-Signature: v1=<captured-hex>'            # different scheme-namespace, same bytes
-H 'X-Signature: sha256=<UPPERCASED>'          # case-sensitive compare vs case-insensitive
-H 'X-Signature: '                             # empty; some validators skip on empty
```
A variant that's ACCEPTED (same response class as the valid signature, different from the
bad-signature baseline) means the parser accepts formats the signer never emits — often
accompanied by comparing only a prefix or skipping verification for unknown schemes.

### 1d. Signature over the wrong bytes (canonicalization gap)

Signatures must cover the exact bytes processed. If the provider signs the raw body but the
receiver re-serializes JSON before verifying (or verifies then re-parses), anything that
preserves semantics but changes bytes slips through — key order, whitespace, duplicate keys,
unicode escapes:

```bash
# take a VALID captured event and re-serialize it differently (still the same JSON):
python3 - "$EV" <<'PY'
import json,sys
d = json.loads(sys.argv[1])
print(json.dumps(d, sort_keys=True, separators=(',',':')))   # canonical-different bytes
PY
# replay THAT with the ORIGINAL signature header. Accepted = verification is not bound to
# the bytes that get processed → there is a window between verify and use.
```
Whether this is exploitable depends on what you can make the two parsers disagree about
(duplicate-key handling, float precision, unicode) — that's a [[business-logic]] question: what
state can a discrepant body drive?

### 1e. Replay — no nonce / timestamp window

```bash
# capture a real delivery to your own tenant, wait past any sane window, replay verbatim:
sleep 3600 && curl -s -X POST "https://webhooks.blobstore.svc/provider" \
  -H 'Content-Type: application/json' -H 'X-Signature: <captured-valid>' -d "$EV" -D -
```
A still-accepted replay hours later means no freshness window (or a huge one) AND no
idempotency key. Severity depends ENTIRELY on what re-processing does — see the impact gate.

### 1f. The honest ceiling: no route oracle = don't blind-fuzz

A signature-gated API-GW receiver often answers EVERY path with the same generic response —
there is no 404-vs-403 tell, no error-based route map, and spraying it just farms generic
responses you cannot interpret (and trips the provider's WAF — the canary trap in
[[controls-and-oracles]]). **State the ceiling and recover the route provider-side instead:**

```bash
# 1. provider dashboard/config: the webhook ENDPOINT URL is configured THERE — if any in-scope
#    dashboard is yours, read the configured URL for each event type.
# 2. delivery logs: your own tenant's deliveries record the exact path+headers each event used.
# 3. IaC in scope repos — the API-GW route is declared in code (GitHub dorking per [[recon]] §4):
grep -rniE 'webhook|events\.http|aws_api_gateway' serverless.yml terraform/ sam/ 2>/dev/null
#   serverless.yml:  functions.<fn>.events[].http.path      ← the literal route
#   Terraform:       aws_api_gateway_resource / aws_api_gateway_method path parts
# 4. leaked config in repos/bundles: the receiver path is a constant in the provider's SDK config
```
A route recovered this way is verified by its RESPONSE BEHAVIOUR to a known-valid event, not by
enumeration — same "verify by what it serves" discipline as [[controls-and-oracles]] Case 5.

## 2. OUTBOUND — the app delivers webhooks to a URL you control

Any feature that POSTs to a URL you register (webhooks, integrations, OAuth callbacks, CI
deploy hooks, payment-provider return URLs) is an SSRF-shaped primitive with a signed, legitimate
request inside:

```bash
# run a local listener (or Burp Collaborator / interactsh for blind confirmation):
socat -v TCP-LISTEN:9999,reuseaddr,fork STDOUT
# register http://YOUR_IP:9999/ as the webhook destination, trigger the event, read what arrives:
```
| Test | What it proves | Severity logic |
|---|---|---|
| **Secret leakage** — read the delivered body/headers: signing secrets, API keys, PII, internal hostnames in the payload | the app trusts its outbound channel with crown jewels and hands them to whoever controls the destination URL | a signing secret or credential in the delivery = High on its own |
| **Scheme/port flexibility** — `http://169.254.169.254/latest/meta-data/`, `http://10.0.0.5:6379/`, `file://` where accepted | the destination is not allowlisted → classic SSRF | internal metadata reach = the full [[ssrf]] chain |
| **Redirect-following** — your URL 302s to `http://169.254.169.254/…` or an internal host | validation happens on the REGISTERED url only, the HTTP client follows elsewhere | same severity as direct internal reach |
| **DNS rebinding on the destination** — a two-answer DNS name (see [[ssrf]] §bypass + the rebinding gate) that validates as your IP then resolves internal | TOCTOU between URL validation and delivery | internal reach again; only counts if the client actually re-resolves |
| **Retry behaviour** — a 500-ing destination gets retried N times, possibly with backoff that shows in your logs | reveals internal retry policy; an endpoint that retries forever on your error = a self-DoS lever and a timing side channel | usually a note; farmable if retries re-deliver a mutated payload (test that!) |

**Impact gate:** outbound-webhook findings pay when the delivery lands somewhere an attacker
shouldn't reach (internal IP, metadata, third party) or carries a secret; "my listener received
the event I subscribed to" is the feature working, not a finding.

## 3. Impact gate (applies to EVERYTHING above)

**A webhook receiver that accepts a forged/replayed event is only a finding if that event CHANGES
STATE.** A `200 OK` on a forged delivery is an authz smell, not a bug. Prove the state change:
the billing record flips, the provisioning job runs, the subscription downgrades, the file-sync
marks someone else's object. Capture before/after state (your own tenant, or an observable
effect you're authorized to observe) the same way you'd prove a mass-assignment — the read-back,
not the acceptance. Chain forged billing events into [[business-logic]] impact framing
(money/value moved, entitlements granted). Then run it through [[validate]] before `findings/`.

## 4. Sender-side taxonomy: does the platform hand you a fetch oracle at all?

Before planning webhook-SSRF on a *sender* platform, establish which of the three oracle tiers the
product actually has — this decides the whole lane in one probe:

| Tier | Signal | SSRF path |
|---|---|---|
| **A — fetch-on-save / test button** | URL validation hits your host, or a `POST .../test` endpoint exists | full oracle immediately (resolver/port/status echoes); an `eventhook` case (fetcher reaches ECS `169.254.170.2`) lived here |
| **B — fetch-on-real-event only** | `POST .../test` → `400 "Test events are not supported"` (a subscription-billing SaaS); delivery fires only on store/billing events | you must manufacture a real event (test purchase, sandbox order) — needs a store-configured app, so often out of reach for a fresh account; the lane is *parked*, not clean |
| **C — no outbound fetch configured by tenant** | no webhook config surface at all | no sender-side SSRF; look for importers/validators instead |

Also snapshot the **validation rules on the URL field itself** the first time you save one:
the SaaS platform now rejects non-HTTPS on create (`"Webhook URL must use HTTPS"`) but a pre-policy object
with `http://` survived — policy-as-of-date is itself information (tells you when they hardened and
what the old endpoints may still accept), and `http://` acceptance matters for any internal
listener that only speaks plaintext.
