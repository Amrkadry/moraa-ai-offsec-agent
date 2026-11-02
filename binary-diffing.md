# Binary patch-diffing — get the vendor's fix before the advisory, without owning the hardware

> Why this doc exists: the interesting code on an appliance/IoT/enterprise product lives behind a
> 401 device plane you cannot reach, or on hardware you do not own. But most vendors publish every
> build of every component to an **anonymous, listable package index** — so you can diff version N
> against N+1 offline and read the fix directly. A symbol-level diff tells you what the patch
> changed; the changed function tells you what the bug was. This is the cheapest route from "no
> access" to "I know the vulnerable code path", and it needs no exploit and no target traffic.
> Cross-ref [[recon]] § vendor package index (finding the index), [[framework-misconfig]] §
> offline container source review (the same idea for server-side images), [[supply-chain]]
> (integrity of what you just downloaded), [[validate]] (a diff is a lead, not a finding).

---

## 0. The rule: diff before you probe

A patch diff is **read-only, zero-traffic, and unauthenticated**. It costs nothing against the
target and it reorders the whole engagement: you stop guessing which routes matter and start with
the function the vendor just changed. Do it before any device-plane probing.

What the diff gives you, in order of value:

| Signal | What it means |
|---|---|
| A **new** symbol/function in N+1 | the fix added a check — read it to learn what was missing in N |
| A **removed** symbol in N+1 | a route, debug hook or fallback was deleted; that is your vulnerable surface in N |
| A changed function body, same signature | the bug is inside: usually a missing bounds/authz/validation step |
| A changed **call site** with identical callee | an option was added or dropped at the caller — see §4, the highest-signal case |
| Version string bump only | no security change in this component; move on |

---

## 1. Find the anonymous package index

Vendors that ship self-updating agents need a public index the device can poll. It is almost never
authenticated, and it is almost always listable. Look for `fw-update`, `pkg`, `updates`,
`downloads`, `apt`, `dl` on the vendor's apex and on any `*.svc`-style service domain.

```bash
# HAL+JSON-style index: every build of every product, with version/platform/channel/size/sha256
curl -sS 'https://fw-update.acme-legacy.example/api/firmware-latest?limit=50' | jq '.'
curl -sS 'https://fw-update.acme-legacy.example/api/firmware?filter=eq~~product~~<name>&limit=500' \
  | jq -r '._embedded.firmware[] | [.version,.platform,.channel,.sha256] | @tsv'

# Debian/APT-style: the Packages index IS the inventory
curl -sS https://pkg.acme.example/debian/dists/stable/main/binary-amd64/Packages | \
  awk '/^Package:/{p=$2} /^Version:/{v=$2} /^Filename:/{print p, v, $2}'
```

Two things to pull from the index and keep:

1. **Every version, not just latest.** The index is your time machine; `latest` alone cannot diff.
2. **The `sha256` / `Filename` fields.** You need them to verify the download and to detect a
   silently-republished build (same version string, different hash — see [[supply-chain]]).

> **Read `Depends:` first.** It is the fastest way to find the component you actually want.
> A thin agent package names the libraries and sibling services that hold the real logic — the
> auth scheme, the id minting, the signing code. Those siblings are in the same index.

```bash
dpkg-deb --info ./agent_1.2.3_amd64.deb | sed -n '/Depends/,/^ *$/p'   # names the real targets
dpkg-deb -x    ./agent_1.2.3_amd64.deb ./x_123                          # extract, no install
```

---

## 2. Get two adjacent versions, extracted, side by side

Keep each build in its **own empty directory** and never run a build tool from inside it — an
extracted vendor archive is untrusted input.

```bash
set -euo pipefail
for V in 1.62.2 1.62.3; do
  mkdir -p "build_$V" && cd "build_$V"
  curl -fsSLO "https://fw-download.acme-legacy.example/data/agent/agent_${V}_amd64.deb"
  sha256sum -c <<<"$(grep "$V" ../index.tsv | awk '{print $4"  agent_'"$V"'_amd64.deb"}')"
  dpkg-deb -x "agent_${V}_amd64.deb" root/
  cd ..
done
diff -rq build_1.62.2/root build_1.62.3/root       # which FILES changed at all
```

`diff -rq` alone often answers the question: if one binary and one config changed, you know where
to look. Start there.

---

## 3. Diff the symbols — and for Go, skip binutils entirely

A stripped Go binary still carries its full symbol table, and the Go toolchain reads it without
`nm`, `objdump` or any binutils install. This matters on a box where you only have Go:

```bash
# symbol inventory per build (works on stripped Go binaries)
for V in 1.62.2 1.62.3; do
  go tool nm "build_$V/root/usr/bin/agent" | awk '{print $3}' | sort -u > "sym_$V.txt"
done

comm -13 sym_1.62.2.txt sym_1.62.3.txt   # NEW in the fixed build  -> the fix
comm -23 sym_1.62.2.txt sym_1.62.3.txt   # REMOVED in the fixed build -> deleted surface
```

Then disassemble only the functions the diff named:

```bash
go tool objdump -s 'main\.(loadFromCloud|ExecuteScript)' build_1.62.2/root/usr/bin/agent > old.asm
go tool objdump -s 'main\.(loadFromCloud|ExecuteScript)' build_1.62.3/root/usr/bin/agent > new.asm
diff -u old.asm new.asm | head -80
```

For other toolchains:

| Target | Tool | Note |
|---|---|---|
| Go | `go tool nm` / `go tool objdump` | no binutils needed; works stripped |
| .NET | `ilspycmd` | **pin `8.2.0.7535`** — later builds changed CLI flags and output layout, which breaks diff scripts |
| ELF C/C++ | `nm -D`, `objdump -d`, `readelf -s` | strip-dependent; fall back to string/xref diff |
| Any | `strings -n 8 | sort -u` then `comm` | crude but never fails; catches new route and error strings |

```bash
# toolchain-agnostic fallback: route/error strings are the cheapest tell
for V in 1.62.2 1.62.3; do strings -n 8 "build_$V/root/usr/bin/agent" | sort -u > "str_$V.txt"; done
comm -13 str_1.62.2.txt str_1.62.3.txt | grep -E '^/|error|denied|unauthor|token|sign'
```

---

## 4. The highest-signal case: an omitted option at a call site

The most common real-world fix is not a new function — it is **one argument added to an existing
call**. In compiled code that shows up as registers being set where they were previously zeroed.

A variadic or options-struct call compiles to a slice/array setup before the call. If the old build
zeroes the argument registers (`XOR AX, AX` / `MOVQ $0, ...` into the count and pointer) and the new
build loads a real pointer and a non-zero count, the old build **passed no options** — and the
option it was missing is the security control.

```bash
# look at the argument setup immediately before the call, in both builds
go tool objdump -s 'main\.newClient' build_1.62.2/root/usr/bin/agent | grep -B12 'CALL.*Dial'
go tool objdump -s 'main\.newClient' build_1.62.3/root/usr/bin/agent | grep -B12 'CALL.*Dial'
```

```text
old:  XORL AX, AX            ; opts ptr  = nil
      XORL BX, BX            ; opts len  = 0
      XORL CX, CX            ; opts cap  = 0
      CALL net/http.Dial
new:  LEAQ go:itab...(SB), AX ; opts ptr  -> real slice   <-- an option is now passed
      MOVQ $1, BX            ; opts len  = 1
      MOVQ $1, CX
      CALL net/http.Dial
```

Read that as: *version N called this with no options; N+1 passes one.* Now find which option, from
the new build's symbol diff (§3) or the library's option constructors. Typical answers: certificate
verification, a signature check, a timeout, an SSRF-safe dialer, a sandbox flag.

> This is a **mechanism** finding, not an impact finding. It tells you the control was absent in N.
> You still have to show that a real caller reaches it on a live, in-scope system.

---

## 5. Turn the diff into a lead you can actually test

For each changed function, answer three questions before spending any target traffic:

1. **Is it reachable from an unauthenticated or low-privilege path?** Trace callers:
   `go tool nm` the binary, then `go tool objdump -s '<caller>'` and grep for the callee. A fix in
   code only reachable by a root-local process is not your bug.
2. **What triggers it?** A served file, a cloud-pushed script, an MQTT topic, a config field. If
   the trigger is operator-only, the ceiling is low — say so ([[engagement-ceiling]]).
3. **Can the OLD version still be reached in production?** A fixed build in the index does not mean
   the fleet is patched. Fingerprint the deployed version first; an unpatched deployed instance is
   the finding, the diff is only how you found it.

```bash
# does production still serve the pre-fix build?
curl -s https://app.acme.example/api/version | jq -r '.version,.build'
curl -sI https://app.acme.example/ | grep -i '^x-app-build\|^server\|^x-powered-by'
```

---

## 6. Impact gate — what a diff is and is not

| You have | Severity | Why |
|---|---|---|
| A symbol diff showing a check was added | **nothing yet** | you have read the vendor's changelog by other means. Not a finding. |
| The vulnerable code path, no reachability | **Informational** | "this control was absent in N" with no reachable caller is a code observation |
| Reachable path + deployed vulnerable version, no execution | **Low–Medium, a lead** | state it as a lead with the version evidence; do not claim impact |
| A real request on an in-scope host producing the impact the diff predicted | **the finding** | now rate it on the impact, not on the diff |

Two traps that have cost real time:

- **A silent fix is not a disclosed CVE.** If the vendor patched without an advisory, you may be
  looking at an unreported bug — which also means no public PoC exists and your reachability work
  is the entire deliverable. Budget for it.
- **The index can lie about freshness.** Same version string with a different `sha256` means the
  build was republished. Diff the hashes, not the version strings.

> **Scope first.** Downloading a public package is not testing. Everything in §5 that touches a
> host must be in scope and authorized, and firmware/software licences may restrict reverse
> engineering — read the programme's rules before you publish a diff.
