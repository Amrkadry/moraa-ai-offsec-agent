#!/usr/bin/env bash
# dns_brute.sh — full-wordlist DNS brute-force across one or more (sub)domains,
# with automatic per-zone wildcard detection so you don't waste an httpx pass
# eyeballing thousands of catch-all false positives.
#
# Lesson learned (acme.example r23 pass, 2026-09-18): a big public-resolver list
# (trickest/resolvers, ~12k resolvers) is SLOWER than ~20 curated major
# resolvers, because most random open resolvers are slow/half-dead and stall
# dnsx's worker threads waiting on them. Always use fast_resolvers.txt (this
# dir) unless you have a reason to believe it's getting rate-limited.
#
# Also: wildcard DNS is common and NOT limited to the zone apex. `*.acme.example`
# wildcards to a generic CloudFront catch-all, but so do several of its own
# sub-zones (`stg.acme.example`, `tw.acme.example`, `store.acme.example`, `corp.acme.example`) while
# siblings at the same visual "depth" (`dev.acme.example`, `svc.acme.example`) are clean
# NXDOMAIN zones. NEVER assume wildcard behavior is uniform across sibling
# subdomains — this script checks every target zone independently.
#
# Usage:
#   ./dns_brute.sh <wordlist> <output-dir> <domain1> [domain2 ...]
#
# Requires: dnsx, curl (for the wordlist auto-download if you pass "assetnote"
# as the wordlist arg), httpx (optional, for the wildcard-signature filter pass)
set -euo pipefail

WORDLIST="${1:?usage: dns_brute.sh <wordlist|assetnote> <output-dir> <domain1> [domain2 ...]}"
OUTDIR="${2:?output dir required}"
shift 2
DOMAINS=("$@")
[ "${#DOMAINS[@]}" -ge 1 ] || { echo "need at least one domain" >&2; exit 1; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
mkdir -p "$OUTDIR"

if [ "$WORDLIST" = "assetnote" ]; then
  WORDLIST="$OUTDIR/2m-subdomains.txt"
  if [ ! -s "$WORDLIST" ]; then
    echo "[*] downloading Assetnote 2m-subdomains.txt wordlist ..." >&2
    curl -sS -o "$WORDLIST" "https://wordlists-cdn.assetnote.io/data/manual/2m-subdomains.txt"
  fi
fi

echo "[*] pre-flight: checking wildcard behavior on each target zone" >&2
CLEAN_ZONES=()
WILD_ZONES=()
for z in "${DOMAINS[@]}"; do
  token="zz$(date +%s%N | tail -c 10)qq"
  ans=$(dig +short "${token}.${z}" A @1.1.1.1 2>/dev/null || true)
  if [ -z "$ans" ]; then
    echo "    $z -> clean (NXDOMAIN for garbage label) — brute-force signal is meaningful" >&2
    CLEAN_ZONES+=("$z")
  else
    echo "    $z -> WILDCARDED ($ans) — every brute-force hit needs an httpx wildcard-signature filter" >&2
    WILD_ZONES+=("$z")
  fi
done

printf "%s\n" "${DOMAINS[@]}" > "$OUTDIR/brute_domains.txt"

echo "[*] launching dnsx multi-domain brute (this can take a while for large wordlists — run in background)" >&2
dnsx -d "$OUTDIR/brute_domains.txt" -w "$WORDLIST" -r "$SCRIPT_DIR/fast_resolvers.txt" \
     -retry 1 -t 600 -auto-wildcard -silent -o "$OUTDIR/brute_raw.txt"

echo "[*] done. Raw hits: $OUTDIR/brute_raw.txt" >&2
if [ "${#WILD_ZONES[@]}" -gt 0 ] && command -v httpx >/dev/null 2>&1; then
  echo "[*] wildcarded zones detected (${WILD_ZONES[*]}) — running httpx + classify_hosts.sh to separate real hits from catch-all noise" >&2
  httpx -l "$OUTDIR/brute_raw.txt" -sc -title -td -server -location -silent -o "$OUTDIR/brute_httpx.txt" || true
  if [ -x "$SCRIPT_DIR/classify_hosts.sh" ]; then
    "$SCRIPT_DIR/classify_hosts.sh" "$OUTDIR/brute_raw.txt" || true
  fi
  echo "[*] review $OUTDIR/brute_raw.txt.classified.tsv — filter out the CATCHALL? cluster before treating anything as a new asset" >&2
fi
