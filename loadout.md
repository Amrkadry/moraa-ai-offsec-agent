# Moraa — Loadout (the toolbox: install it once, smoke-test it always)

> **Tier 2 — operator layer.** This doc describes *one* working setup, published as a
> reference rather than a requirement. Yours will differ; nothing in the methodology
> depends on it. See [CUSTOMIZATION.md](CUSTOMIZATION.md).

> Why this doc exists: engagements lose their first 30 minutes to "which install command was it",
> and lose hours more to a silent tool failure discovered mid-hunt (the `curl -o` stale-file trap
> in [[controls-and-oracles]] is the canonical example). Install once, then PROVE the kit works
> with the smoke test at the bottom — before you need it against a real target.
> Cross-ref [[recon]] (the workflow that consumes this kit), [[burp-mcp]] (Burp automation),
> [[cheatsheet]] (speed once the kit is up).

## 0. Base environment — WSL/Kali

All work runs in **WSL/Linux bash** (standing rule). Windows-native invocations are the
exception, and §4 lists the two gotchas that bite when you forget.

```bash
# WSL2 + Kali tooling baseline (Debian/Ubuntu WSL also fine)
sudo apt update && sudo apt -y install \
  curl wget git unzip jq build-essential python3 python3-pip python3-venv \
  nmap whois dnsutils netcat-openbsd socat rlwrap gobuster seclists wordlists \
  nikto sqlmap whatweb wafw00f hydra john hashcat
```

## 1. The Go tooling (recon + hunting workhorses)

```bash
# Go itself (if missing) — then install everything with one block
sudo apt -y install golang-go || true
export GOPATH="$HOME/go"; export PATH="$PATH:$HOME/go/bin"      # also add this line to ~/.bashrc

go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install -v github.com/ffuf/ffuf/v2@latest
go install -v github.com/lc/gau/v2/cmd/gau@latest
go install -v github.com/tomnomnom/waybackurls@latest
go install -v github.com/tomnomnom/anew@latest
go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest
nuclei -update-templates                                         # templates download/update is a separate step — run it weekly                                        # template update is a separate step, run it weekly
```
Configure subfinder providers once (`~/.config/subfinder/provider-config.yaml`) — free API keys
(Shodan/Censys/ChaCha keys) multiply your passive yield; the provider file is personal, never
commit it.

## 2. Wordlists worth having (and where they live)

```bash
ls /usr/share/wordlists/ /usr/share/seclists/ 2>/dev/null       # apt 'wordlists'/'seclists' put them here
# SecLists if apt didn't bring it:
git clone --depth 1 https://github.com/danielmiessler/SecLists.git ~/wordlists/SecLists

# Assetnote DNS/directory lists (recon.md's DNS brute uses these):
curl -sO https://wordlists-cdn.assetnote.io/data/automated/best-dns-wordlist.txt
curl -sO https://wordlists-cdn.assetnote.io/data/automated/httparchive_subdomains_2026_02_27.txt
curl -sO https://wordlists-cdn.assetnote.io/data/automated/httparchive_directories_1m_2024.txt

# the personal all-in-one fuzz list this estate uses (recon.md § content fuzz):
ls "D:/wordlists/Fuzz_all.txt"   # from WSL: /mnt/d/work/claude/...
```
Keep personal lists OUT of the skill repo (size + licensing); reference them by path in
engagement configs. `recon.md` holds the canonical paths — this doc just gets them installed.

## 3. Burp Suite configuration (Windows-side Burp ↔ WSL tooling)

```bash
# Burp runs on Windows host at 127.0.0.1:8080. From WSL2, "localhost" usually reaches it;
# if not, use the Windows host IP:
HOST_IP=$(grep -m1 nameserver /etc/resolv.conf | awk '{print $2}')   # WSL2 NAT mode
#   WSL2 mirrored networking (Win11): 127.0.0.1 works directly — test both.
#   Win10 home: cloudflared/mirrored: /etc/resolv.conf nameserver = the vEthernet gateway IP.

# point tooling through Burp when you want requests recorded:
httpx -l live.txt -proxy http://$HOST_IP:8080
ffuf -u https://HOST/FUZZ -w words.txt -x http://$HOST_IP:8080
# curl:
curl -sk --proxy http://$HOST_IP:8080 https://TARGET/

# trust Burp's CA inside WSL so -k isn't needed (httpx/nuclei honor the system store):
curl -sk --proxy http://$HOST_IP:8080 http://burp/cert -o burp.der
openssl x509 -inform DER -in burp.der -out burp.pem
sudo cp burp.pem /usr/local/share/ca-certificates/burp.crt && sudo update-ca-certificates
```
Upstream scope discipline lives in [[burp-mcp]]: when the Burp MCP is connected, prefer
sitemap/repeater over re-crawling; keep scope strictly in-program.

## 4. WSL / Windows gotchas — THIS ESTATE HAS HIT BOTH

1. **`node` may be the WINDOWS node.** If npm was installed on Windows, WSL's `node` can resolve
   to `node.exe` (check `which node`). Windows node cannot read `/mnt/c/...`-style WSL paths and
   mangles POSIX argument semantics — a JS helper script that "runs but finds no files" is
   usually this. Fix: install node inside WSL (`sudo apt -y install nodejs npm`) and confirm
   `which node` points into WSL (`/usr/bin/node`), not `/mnt/c/...`.
2. **Windows `python` cannot read `/c/...` or `/mnt/...` paths.** `python` in a PowerShell/
   cmd context doesn't understand WSL path syntax, so a script path that looks right in WSL
   terms fails on Windows python with "can't open file". The estate rule: **always `python3`
   inside WSL** — never reach for Windows python, and never invoke `.py` helpers from PowerShell.
   Sanity check: `which python3` must be `/usr/bin/python3`.
3. Line endings: repos force LF for scripts (`.gitattributes`); a CRLF shebang silently breaks
   `./script.sh` in WSL. If a copied script won't run: `sed -i 's/\r$//' script.sh`.

## 5. Python / node helpers worth having

```bash
# python3 (stdlib-only house rule for anything we commit — see AGENTS.md):
#   throwaway helper scripts may use requests locally, but anything committed to scripts/ stays stdlib-only
# the repo's own audited helpers (stdlib only, offline-safe):
python3 scripts/favicon_hash.py --help
python3 scripts/jwt_expiry.py --help
# node helpers (WSL-installed node only — see gotcha #1):
sudo apt -y install nodejs npm
npm install -g prettier           # JS de-obfuscation/pretty-print for bundle mining (js-analysis.md)
```

## 6. Smoke test — "is my tooling actually working?" (run before every engagement)

Two minutes now beats a dead oracle discovered at hour three. **Runs fully offline** against a
local throwaway server — no third-party traffic:

```bash
set -e
# 1. local target up
mkdir -p /tmp/smoketool && echo "SMOKE-OK-7f3a" > /tmp/smoketool/canary.txt
python3 -m http.server 8899 --directory /tmp/smoketool >/dev/null 2>&1 & SRV=$! ; sleep 1

# 2. each binary EXISTS and EXECUTES (a --version that errors = broken install)
for t in subfinder httpx dnsx ffuf gau waybackurls nuclei anew jq nmap; do
  printf '%-12s' "$t"; $t -version >/dev/null 2>&1 && echo OK || echo "MISSING/BROKEN"
done

# 3. the PIPELINE works — this is what actually breaks (perms, PATH, template dir)
printf '127.0.0.1\n' | httpx -silent -ports 8899 | grep -q 127.0.0.1 && echo "httpx live-probe OK"
curl -s http://127.0.0.1:8899/canary.txt | grep -q SMOKE-OK-7f3a && echo "fetch OK"
ffuf -u http://127.0.0.1:8899/FUZZ -w <(printf 'canary.txt\nnope.txt\n') -mc all -s | grep -q canary.txt \
  && echo "ffuf OK"
ls ~/nuclei-templates >/dev/null 2>&1 || ls ~/go/pkg/dev/nuclei-templates >/dev/null 2>&1 \
  && echo "nuclei templates present" || echo "nuclei templates MISSING (nuclei -update-templates)"

# 4. python3 is WSL python3 (gotcha #2) and the repo checker passes
which python3 | grep -q '^/usr/' && echo "python3 is WSL-native"
python3 scripts/check_docs.py && echo "skill library structurally sound"

# 5. cleanup
kill "$SRV" 2>/dev/null; rm -rf /tmp/smoketool; echo "smoke done"
```
A failed line = fix before the engagement, not during. Anything the smoke test can't check
(Burp MCP connectivity, Collaborator egress) is checked at engagement start per [[burp-mcp]].
