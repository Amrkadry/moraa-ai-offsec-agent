# Request signing / anti-bot token reversal

Burp Repeater returns `401 invalid signature` or `403 bot detected` on a replay that the
browser/app does fine. There's a `sign`/`sig`/`X-Signature`/`nonce`/`X-Acf-Sensor-Data` or
encrypted-body field the client computes. This gets you **just enough** of the signer to
reproduce the request outside the client.

> **Why it pays**: the signature itself is not the bug — it's the lock on a door. The API
> behind it is one the program assumed only their own client would reach, so it's usually
> under-tested for IDOR/BOLA/mass-assignment/business-logic. **Never report "I reversed your
> signing algorithm" alone — that's N/A** (`validate.md`). Report the bug you reach *through* it.

---

## Step 0 — packet-first gate (kills ~half of "I need to reverse this")

Run this BEFORE opening DevTools Sources. Most of the work is proving you *don't* need to reverse anything.

```
1. Capture the real request     Burp proxy / mitmproxy / DevTools Network → Copy as cURL
2. Replay it UNCHANGED           → 200? NOT SIGNED. Skip reversing, go fuzz it.
3. Replay it again 5 min later   → still 200? No freshness check — wide/infinite replay window.
4. Mutate ONE non-sign field, keep sign as-is (e.g. change an id in the body)
   → 200? sign does NOT cover that field → tamper freely, done.
   → 401? sign covers it → continue below.
```

A signature that never expires, or omits the endpoint/payload it's supposedly protecting, is
itself the bug (see CoinMate example below) — found entirely by step 0, no reversing.

## Stage spine

`locate` (find where sign is written) → `recover` (de-shell only the blocking layer) →
`isolate inputs` (which fields are attacker-mutable) → `validate` (prove your re-impl matches) →
`replay` (fuzz through it).

### Locate — Chrome DevTools

```
Sources → XHR/fetch Breakpoints → + → paste the endpoint path → trigger the action
  → walk UP the Call Stack; the frame that mutates headers/body = writer
Sources → Ctrl+Shift+F (search all loaded scripts) for: sign  X-Signature  .sign =  headers[
  → {} pretty-print the minified file first so line numbers hold still
```

### Recover — de-shell only what blocks you

| Shell | Minimal move |
|---|---|
| webpack bootstrap | breakpoint inside the target module, read the local closure — don't unpack the whole bundle |
| string-array obfuscation (`_0x4a2b[12]`) | print the decoder array in console, or breakpoint + read decoded values live |
| Web Worker / `postMessage` | breakpoint the worker script; treat the `postMessage` payload as the contract |
| wasm | hook the JS↔wasm boundary, capture inputs/outputs — don't decompile wasm |
| JSVMP (custom bytecode VM) | don't reverse the VM — go black-box: hook input+output |

**Black-box beats decompilation 90% of the time.** You don't need the HMAC math — you need the
input tuple and a way to *call* the function:

```javascript
// grab a reference at a breakpoint inside the builder, then call it from console for ANY payload
window.__sign = signFn;
window.__sign({id: 999, ts: Date.now()})

// or hook it to log every real sign(input)->output pair the app produces:
const orig = CryptoSigner.prototype.sign;
CryptoSigner.prototype.sign = function(...a){ const out = orig.apply(this,a);
  console.log('SIGN', JSON.stringify(a), '=>', out); return out; };
```

### Isolate inputs — decides whether replay is even possible

| Input | Attacker-mutable? | Implication |
|---|---|---|
| timestamp/nonce | yes (you generate) | fine, regenerate per replay — check validity window |
| deviceId/uuid | yes, once per session | grab once, pin it |
| body/path | yes | **the prize** — if sign covers it, mutate + re-sign to fuzz IDOR/mass-assign |
| secret key | no (you extract it) | if baked into JS/APK → forge any request offline |

```bash
# hunt the bundle for a baked secret before doing anything clever
wget -q -r -l1 -A '*.js' -P /tmp/js/ "https://target.com" 2>/dev/null
grep -rnoE "appSecret|secretKey|signKey|HMAC|['\"][A-Za-z0-9+/]{24,}={0,2}['\"]" /tmp/js/ | head
```

- Secret in the client → forge any request offline, full replay+fuzz.
- Secret server-side but signer callable from the page → sign any payload while page is open
  (headless-browser bridge).
- Secret server-side + signer uncallable → replay UNCHANGED only; still check: does sign omit
  path/body (CoinMate pattern → forge anyway)? Does it never expire (report the replay-window bug)?

### Validate — prove equivalence before trusting a Python re-impl

The two usual killers: JSON key ordering/whitespace, and input concatenation order. Diff the
**pre-hash message string**, not the final hash, when your digest is wrong.

```python
import hmac, hashlib, json
def sign(body, ts, nonce, secret):
    payload = json.dumps(body, separators=(',', ':'), sort_keys=False)  # match JS exactly
    return hmac.new(secret, f"{ts}{nonce}{payload}".encode(), hashlib.sha256).hexdigest()
assert sign(captured_body, captured_ts, captured_nonce, SECRET) == observed_sig
```

### Replay — the request you'll actually fuzz

```python
import requests, time, uuid
def signed_request(body):
    ts, nonce = str(int(time.time()*1000)), uuid.uuid4().hex
    sig = sign(body, ts, nonce, SECRET)
    return requests.post(url, json=body,
        headers={"X-Timestamp": ts, "X-Nonce": nonce, "X-Signature": sig})

for victim_id in range(1000, 1100):        # IDOR sweep behind the signature
    r = signed_request({"orderId": victim_id})
    if r.status_code == 200 and "not authorized" not in r.text:
        print(f"IDOR: order {victim_id}", r.json())
```

> Bridge option when the secret stays server-side: keep a headless browser open, expose the
> page's own `sign()` via a tiny local HTTP shim, have the Python fuzzer call out to it.

## Anti-bot SDKs (Akamai / DataDome / PerimeterX)

Same spine, harder shell — full sensor-blob reversal is a week-long research project, **out of
scope for a single bounty**. Two realistic paths instead:
- **Reuse, don't reverse**: grab one fresh valid token from a real browser session, replay within
  its validity window — enough to prove the protected endpoint is reachable, then hunt IDOR/auth
  there.
- **Headless bridge**: Selenium/Playwright mints the token, hands it to the Python fuzzer.

If the anti-bot itself is misconfigured — token never expires, token from account A validates
account B's requests, the protected endpoint is also reachable unprotected on a sibling host —
report *that*, no reversing required.

## Mobile variant (APK)

Same locate→recover→isolate→validate→replay spine, packet-first still wins: drive the app,
watch Burp/mitmproxy, only `jadx`/`frida` the APK when the packet is encrypted or unreplayable
(`mobile-pentest` / `offensive-mobile` skill for the static/dynamic tooling).

## What's submittable vs N/A

| Finding | Verdict |
|---|---|
| "I reversed your signing algorithm" | **N/A** — not a vuln alone |
| Signed request replays unchanged forever (no freshness) | Low/Medium — replay-window bug |
| Sign omits endpoint/payload → forge without the secret (CoinMate pattern) | Medium/High — forgery |
| Secret hardcoded in JS/APK → forge any request | Medium alone; High/Critical chained to the API it unlocks |
| Reached protected API → found IDOR/BOLA/mass-assign there | **High/Critical — the real prize** |
| One user's anti-bot token validates another user's request | Medium — broken token binding |

Once through the signature: route to `idor-access-control.md`, `auth-oauth.md`,
`business-logic.md`, or `parameter-deep-dive.md` § HPP for the actual bug, then `validate.md` before
writing it up.
