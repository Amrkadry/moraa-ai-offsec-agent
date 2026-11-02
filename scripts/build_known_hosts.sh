#!/usr/bin/env bash
# build_known_hosts.sh — extract every hostname already mentioned anywhere in an
# engagement's tracking files into flat, grep-able per-TLD lists.
#
# WHY: on a long-running engagement, "is this host already tested?" gets answered by
# re-reading multi-thousand-line coverage.md/HUNT-QUEUE.md files every time — expensive
# in agent tokens and error-prone (easy to miss a mention). This turns that into a single
# `grep -f known_hosts_<tld>.txt candidates.txt -v` to isolate genuinely new hosts.
#
# Usage:
#   ./build_known_hosts.sh <engagement-dir> [tld1 tld2 ...]
# Example:
#   ./build_known_hosts.sh "/d/Moraa/.../engagements/acme.example" acme.example acme-legacy.example acme-nms.example
#
# Output: <engagement-dir>/recon/known_hosts_<tld>.txt (one hostname per line, sorted -u)
# Safe to re-run any time — fully regenerates from source files, never hand-edited.

set -euo pipefail

ENGAGEMENT_DIR="${1:?usage: build_known_hosts.sh <engagement-dir> [tld...]}"
shift || true
TLDS=("${@:-acme.example acme-legacy.example acme-nms.example}")
# handle the default-array-as-one-string case from the line above
if [ "${#TLDS[@]}" -eq 1 ] && [[ "${TLDS[0]}" == *" "* ]]; then
  read -r -a TLDS <<< "${TLDS[0]}"
fi

OUT_DIR="$ENGAGEMENT_DIR/recon"
mkdir -p "$OUT_DIR"

# Every place a hostname could plausibly have been written down.
# NUL-delimited throughout — engagement paths on this machine contain spaces
# ("...Dorking in finding in open source codes..."), so plain word-splitting breaks.

for tld in "${TLDS[@]}"; do
  esc_tld=$(printf '%s' "$tld" | sed 's/\./\\./g')
  out="$OUT_DIR/known_hosts_${tld}.txt"
  find "$ENGAGEMENT_DIR" -type f \( -name "*.md" -o -name "*.txt" -o -name "*.json" \) -print0 2>/dev/null \
    | { xargs -0 grep -ohiE "[a-z0-9_-]+(\.[a-z0-9_-]+)*\.${esc_tld}" 2>/dev/null || true; } \
    | tr 'A-Z' 'a-z' \
    | sed -E 's/^\*\.//' \
    | sort -u \
    > "$out"
  count=$(wc -l < "$out" | tr -d ' ')
  echo "[$tld] $count known hosts -> $out"
done

echo
echo "Use: grep -vFxf recon/known_hosts_<tld>.txt fresh_candidates.txt   # isolates genuinely NEW hosts"
