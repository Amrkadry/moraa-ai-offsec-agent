#!/usr/bin/env bash
# enum_diff.sh — enumerate a domain across sources, then output ONLY hosts that are
# genuinely new (not already in the known_hosts registry). Run build_known_hosts.sh
# first so the diff has something to diff against.
#
# WHY: repeated full CT-log/subfinder re-pulls on the same domain mid-engagement mostly
# reproduce results already triaged — burns agent turns re-discovering the same 300+
# host list instead of surfacing the handful of names that actually appeared since the
# last pass.
#
# Usage:
#   ./enum_diff.sh <domain> <engagement-dir> [subfinder|full]
# Example:
#   ./enum_diff.sh acme.example "/d/Moraa/.../engagements/acme.example" full
#
# Output: <engagement-dir>/recon/new_candidates_<domain>_<YYYY-MM-DD>.txt
# Also appends the full raw union into known_hosts_<domain>.txt so the registry stays current.

set -euo pipefail

DOMAIN="${1:?usage: enum_diff.sh <domain> <engagement-dir> [subfinder|full]}"
ENGAGEMENT_DIR="${2:?usage: enum_diff.sh <domain> <engagement-dir> [subfinder|full]}"
MODE="${3:-full}"
DATE_TAG=$(date +%F)

OUT_DIR="$ENGAGEMENT_DIR/recon"
mkdir -p "$OUT_DIR"
KNOWN="$OUT_DIR/known_hosts_${DOMAIN}.txt"
touch "$KNOWN"

TMP=$(mktemp)
trap 'rm -f "$TMP"' EXIT

echo "[*] Enumerating $DOMAIN (mode=$MODE)..." >&2

# passive, always
command -v subfinder >/dev/null && subfinder -d "$DOMAIN" -all -recursive -silent >> "$TMP" 2>/dev/null || true

# crt.sh + certspotter fallback (cheap, always worth it)
curl -sk "https://crt.sh/?q=%25.${DOMAIN}&output=json" 2>/dev/null \
  | grep -oiE "[a-zA-Z0-9_*.-]+\.${DOMAIN}" >> "$TMP" || true
curl -sk "https://api.certspotter.com/v1/issuances?domain=${DOMAIN}&include_subdomains=true&expand=dns_names" 2>/dev/null \
  | grep -oiE "[a-zA-Z0-9_*.-]+\.${DOMAIN}" >> "$TMP" || true

if [ "$MODE" = "full" ]; then
  command -v assetfinder >/dev/null && assetfinder --subs-only "$DOMAIN" >> "$TMP" 2>/dev/null || true
  command -v chaos >/dev/null && chaos -d "$DOMAIN" -silent >> "$TMP" 2>/dev/null || true
fi

# normalize: lowercase, strip leading wildcard/crt.sh artifact glue, dedupe
UNION="$OUT_DIR/.enum_union_${DOMAIN}.tmp"
tr 'A-Z' 'a-z' < "$TMP" \
  | sed -E 's/^\*\.//' \
  | grep -E "\.${DOMAIN//./\\.}\$|^${DOMAIN//./\\.}\$" \
  | sort -u > "$UNION"

# snapshot what was already known BEFORE this pass updates the registry
OLD_KNOWN=$(mktemp)
sort -u "$KNOWN" > "$OLD_KNOWN"

# the actual output: what's new THIS pass vs everything ever seen before this run
NEW_OUT="$OUT_DIR/new_candidates_${DOMAIN}_${DATE_TAG}.txt"
comm -23 "$UNION" "$OLD_KNOWN" > "$NEW_OUT"
rm -f "$OLD_KNOWN"

# fold the full union into the registry (cumulative source of truth), AFTER the diff
cat "$KNOWN" "$UNION" | sort -u -o "$KNOWN"
rm -f "$UNION"

count=$(wc -l < "$NEW_OUT" | tr -d ' ')
echo "[$DOMAIN] $count new candidate(s) not in known_hosts_${DOMAIN}.txt -> $NEW_OUT" >&2
echo "[*] known_hosts_${DOMAIN}.txt now has $(wc -l < "$KNOWN" | tr -d ' ') total entries" >&2
echo
echo "Next: cat $NEW_OUT | httpx -silent -sc -title -td -ip -cname -server -location -favicon"
echo "  (or ./classify_hosts.sh $NEW_OUT  for automatic wildcard-catchall detection)"
