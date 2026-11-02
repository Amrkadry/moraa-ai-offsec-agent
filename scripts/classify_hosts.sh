#!/usr/bin/env bash
# classify_hosts.sh — resolve + fingerprint a candidate list and auto-flag the
# wildcard-DNS / generic-fallback-redirect trap (the exact thing that made *.acme-nms.example
# look "all live" under a shallow scan: any label resolves, then L7-routes by Host
# header to a generic marketing page that looks identical across hundreds of hosts).
#
# LOGIC: cluster live hosts by (status_code, content_length, title). Whichever cluster
# is the LARGEST is almost always the catchall/wildcard-fallback signature, not a real
# distinct app — auto-tag it CATCHALL. Everything else is a real per-host response and
# gets tagged LIVE-DISTINCT. Always eyeball the CATCHALL bucket once per engagement to
# confirm the assumption holds (it can be wrong on a small candidate set).
#
# Usage:
#   ./classify_hosts.sh <candidates-file>
# Output: <candidates-file>.classified.tsv  (host, status, cl, title, tag)

set -euo pipefail

CANDIDATES="${1:?usage: classify_hosts.sh <candidates-file>}"
OUT="${CANDIDATES}.classified.tsv"
RAW=$(mktemp)
trap 'rm -f "$RAW"' EXIT

echo "[*] Fingerprinting $(wc -l < "$CANDIDATES" | tr -d ' ') candidates..." >&2

# -sc status, -cl content-length, -title, -td tech, -silent quiet; tab-separated
httpx -l "$CANDIDATES" -silent -sc -cl -title -td -o "$RAW" 2>/dev/null || true

if [ ! -s "$RAW" ]; then
  echo "[!] No live hosts (or httpx not installed) — nothing to classify." >&2
  exit 0
fi

# build a signature per line = status+cl (title too noisy w/ per-host session ids sometimes)
# then find the modal (most common) signature = the catchall cluster
python3 - "$RAW" "$OUT" <<'PYEOF'
import sys, re, collections

raw_path, out_path = sys.argv[1], sys.argv[2]
rows = []
sig_counts = collections.Counter()

line_re = re.compile(r'^(\S+)\s+\[(\d+)\]\s+\[([^\]]*)\]\s+\[([^\]]*)\]')
with open(raw_path, encoding='utf-8', errors='replace') as f:
    for line in f:
        line = line.strip()
        if not line:
            continue
        m = line_re.match(line)
        if not m:
            # fallback: keep the raw line, unclassifiable
            rows.append((line, '?', '?', '?', None))
            continue
        host, status, cl, title = m.groups()
        sig = (status, cl)
        sig_counts[sig] += 1
        rows.append((host, status, cl, title, sig))

catchall_sig = sig_counts.most_common(1)[0][0] if sig_counts else None
catchall_count = sig_counts.most_common(1)[0][1] if sig_counts else 0

with open(out_path, 'w', encoding='utf-8') as out:
    out.write("host\tstatus\tcl\ttitle\ttag\n")
    for host, status, cl, title, sig in rows:
        if sig is None:
            tag = "UNPARSED"
        elif sig == catchall_sig and catchall_count >= 3:
            tag = "CATCHALL?"
        else:
            tag = "LIVE-DISTINCT"
        out.write(f"{host}\t{status}\t{cl}\t{title}\t{tag}\n")

distinct = sum(1 for r in rows if r[4] != catchall_sig or catchall_count < 3)
print(f"[*] Modal signature (status={catchall_sig[0] if catchall_sig else '?'}, "
      f"cl={catchall_sig[1] if catchall_sig else '?'}) seen {catchall_count}x -> tagged CATCHALL?",
      file=sys.stderr)
print(f"[*] {distinct} host(s) tagged LIVE-DISTINCT -> review those first", file=sys.stderr)
PYEOF

echo "[*] Wrote $OUT" >&2
echo
echo "Review: awk -F'\\t' '\$5==\"LIVE-DISTINCT\"' $OUT"
echo "Sanity-check the CATCHALL? bucket once — confirm a few really are the generic fallback"
echo "before discarding the whole cluster (per acme-nms.example lesson: verify, don't just trust the count)."
