# Moraa — Supply-chain & artifact integrity (firmware / packages / CI)

> Folds in our confirmed findings — the vendor `fw-update`/`fw-download` served over **plaintext HTTP,
> no redirect, no HSTS** (Med, MITM firmware-substitution surface); Nerves toolchain download with **no
> content hash/sig + no HTTPS enforce + redirect downgrade** (A08/CWE-494, build-host RCE) — plus
> dependency-confusion and package-repo patterns. Cross-ref [[ssrf]] (redirect downgrade), [[recon]] (artifact hosts).

## The class: can an attacker change what a device/build fetches, without detection?
Distinct from web bugs — the victim is a **device, an installer, or a build pipeline** that fetches
an artifact (firmware, toolchain, package, dependency) and trusts it. The finding is a missing or
bypassable integrity control on that fetch. Score honestly: it's usually a **missing-baseline-control**
(needs an on-path/MITM position or a name-squat to exploit); demonstrate the gap, don't overclaim RCE
you didn't achieve.

## Firmware / update-channel checklist
1. **Transport:** is the metadata API and the binary served over plain `http://`? Does it 301→HTTPS?
   Is HSTS set (compare against a sibling that has it)?
   ```bash
   curl -sI  http://fw-update.TARGET/api/firmware-latest?...   # 200 no-redirect + no HSTS = finding
   curl -sIL http://fw-download.TARGET/data/....bin            # num_redirects=0, streams in the clear?
   curl -sI  https://sso.TARGET/ | grep -i strict-transport    # the host that DOES set HSTS = your contrast
   ```
2. **Integrity as served:** does the API ship a `sha256`/signature for the image — and over the **same
   cleartext channel**? (A checksum delivered over the channel you're MITMing is self-defeating — note it.)
3. **Signature verification is client-side** (in the device/updater) and usually **can't be tested
   black-box** — say so explicitly; if signatures are verified on-device, practical impact drops to Low.
4. **Redirect downgrade:** does the download follow a redirect from HTTPS→HTTP, or to an
   attacker-influenceable host? (Nerves: redirect downgrade defeated the transport assumption.)
5. **Channel/entitlement:** can you pull `dev`/`beta`/`restricted` builds you shouldn't? Verify the
   restriction is REAL before reporting — our first pass wrongly called a "restricted bypass": the
   `restricted` tag was decorative build-metadata, `dev`/`internal` channels returned 0 items, no
   control existed to bypass. **Confirm the control exists before claiming you bypassed it.**
6. **Firmware what-to-fetch influence:** an unauth way to change which image a device is told to fetch
   (version/model/mac param that alters the returned download URL) = **critical supply-chain**. Hunt the
   device firmware-check API's params.

## Package repository (Artifactory / apt / npm / pypi mirrors)
- **Intended-public vs not:** a browsable apt/pypi mirror is usually *by design* (that's how the software
  installs) → Low/Info unless it exposes **non-public packages, creds, or an admin API**. Our
  `apt.artifacts.acme.example` was a public Debian mirror = not a finding.
- **Artifactory:** try `/artifactory/api/repositories`, `/api/system/ping`, `/api/security/users`,
  anonymous deploy (`PUT`), and whether a single-repo vhost still exposes the REST API.
- **Upload/overwrite:** can you write to a repo anonymously or overwrite an existing artifact version?
- **Metadata leak:** `.git`, `.env`, build manifests, CI config in the artifact host.

```bash
# Artifactory enum — read first, write LAST (a PUT is a state change; only on your own/scratch repo)
curl -s  "https://artifacts.TARGET/artifactory/api/repositories" | jq -r '.[].key' 2>/dev/null
curl -s  "https://artifacts.TARGET/artifactory/api/system/ping"
curl -si "https://artifacts.TARGET/artifactory/api/security/users" | head -3   # anon user list = finding
# anonymous deploy check (use a SCRATCH repo name; a 201 on a real repo is a real write — don't)
curl -si -X PUT "https://artifacts.TARGET/artifactory/moraa-probe-scratch/probe.txt" -d 'probe' | head -3
# does a single-repo vhost still expose the REST API?
curl -s "https://apt.artifacts.TARGET/artifactory/api/repositories" | head -3

# apt/npm mirror: intended-public vs non-public packages leaking
curl -s "https://apt.TARGET/dists/stable/main/binary-amd64/Packages" | grep -E '^Package:|^Filename:' | head -20
```

**Impact gate:** a browsable public mirror of intended-public packages is by design (Low/Info).
The finding is non-public packages readable, anonymous WRITE on a real repo, an admin API, or
creds in metadata — demonstrate with one read, don't dump the index.

## Dependency confusion / substitution (name-squat, no MITM needed)
- Harvest internal package names from bundles/lockfiles/`package.json`/`requirements.txt`/build logs.
- Check if any internal name is **unregistered on the public registry** (npm/pypi/rubygems/maven) — if
  so, a higher-version public package of that name may be pulled by the victim's build → RCE in CI.
  (Report the unclaimed name + the resolver behavior; do NOT publish a malicious package — squat the
  name benignly / just prove it's claimable, per program rules.)
- **Scope/registry confusion:** `@internal/x` resolving to public registry; a `.npmrc`/`pip.conf`
  that lists the public registry as a fallback.

```bash
# is the internal name claimable on the public registry? (a 404/enotfound = claimable)
npm view "@target-internal/whatever" version 2>&1 | head -2
npm view "target-internal-pkg" version 2>&1 | head -2
curl -s -o /dev/null -w '%{http_code}\n' "https://pypi.org/pypi/target-internal-pkg/json"
# where does the build resolve from? (leaked .npmrc/pip.conf in bundles/repos — read, don't publish)
grep -rE 'registry=|index-url' <leaked-config> 2>/dev/null
# resolver behavior: register the name BENIGNLY (placeholder, no code) only if program rules allow,
# and only in your own namespace — never a malicious/higher-version lookalike.
```

**Impact gate:** report = name is unclaimed + the victim build demonstrably resolves the public
registry as fallback. Do NOT publish a malicious package — a benign placeholder (or just the
unclaimed-name evidence) proves it. No build resolves it = theoretical, don't report.

## CI/CD & build pipeline
- Leaked CI tokens / registry creds in bundles, artifact hosts, or config → push malicious artifact.
- Post-web-foothold: a web shell that can reach the internal registry or the CI runner = supply-chain pivot.

```bash
# leaked CI tokens in bundles/artifact hosts — find, prove scope with ONE read, then disclose for rotation
# (never print full token values — mask to prefix+length in any notes or findings)
grep -rohE 'ghp_[A-Za-z0-9]{20,}|glpat-[A-Za-z0-9_-]{20,}|AKIA[0-9A-Z]{16}' <bundle-dir> 2>/dev/null | sort -u | awk '{print substr($0,1,8) "...(" length($0) " chars)"}'
# prove scope of one hit (GitHub PAT): does it read the org? (token only in your local env, not in notes)
curl -s -H "Authorization: token $LEAKED_PAT" "https://api.github.com/user" | jq -r '.login'
# redirect downgrade on a downloaded toolchain (HTTPS entry -> HTTP hop)
curl -sIL "https://downloads.TARGET/tool/toolchain.tar.gz" | grep -E '^HTTP|^location'
```

## Report framing
State the control that is missing/bypassable, the position required to exploit (MITM / name-squat /
CI access), and what you PROVED vs OBSERVED. Remediation is usually: enforce HTTPS + HSTS + redirect
pinning, sign artifacts and verify signatures on the client, deliver hashes out-of-band, and register
(or reserve) all internal package names publicly.
