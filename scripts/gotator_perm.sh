#!/usr/bin/env bash
# gotator_perm.sh — permutation/alteration scan seeded from every known-live host,
# resolved and ready for wildcard-signature triage.
#
# Usage:
#   ./gotator_perm.sh <seed-hosts-file> <output-dir> [perm-wordlist]
#
# If perm-wordlist is omitted, uses the bundled infra_perms.txt (dev/stg/qa/uat/v2/
# new/old/internal/api/backup/... ~290 devops/infra words).
#
# IMPORTANT (lesson from acme.example r23, 2026-09-18): permutation output resolved against
# a wildcarded parent zone is almost pure noise (e.g. "dev-foo.acme.example" resolves for
# EVERY possible "foo" because *.acme.example itself wildcards to a generic catch-all).
# ALWAYS run classify_hosts.sh (or an equivalent content-signature filter) on the
# resolved output before treating anything as a real new asset — never trust bare
# DNS resolution alone on a permutation candidate list.
#
# Requires: gotator, dnsx on PATH.
set -euo pipefail

SEED="${1:?usage: gotator_perm.sh <seed-hosts-file> <output-dir> [perm-wordlist]}"
OUTDIR="${2:?output dir required}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PERMS="${3:-$SCRIPT_DIR/infra_perms.txt}"

mkdir -p "$OUTDIR"

echo "[*] generating depth-1 permutations from $(wc -l < "$SEED") seed hosts x $(wc -l < "$PERMS") perm words" >&2
gotator -sub "$SEED" -perm "$PERMS" -depth 1 -mindup -silent -t 200 | sort -u > "$OUTDIR/gotator_candidates.txt"
echo "[*] $(wc -l < "$OUTDIR/gotator_candidates.txt") unique candidates -> $OUTDIR/gotator_candidates.txt" >&2

echo "[*] resolving with dnsx (this can take several minutes for 100k+ candidates)" >&2
dnsx -l "$OUTDIR/gotator_candidates.txt" -r "$SCRIPT_DIR/fast_resolvers.txt" \
     -retry 1 -t 500 -resp -silent -o "$OUTDIR/gotator_resolved.txt"

awk '{print $1}' "$OUTDIR/gotator_resolved.txt" | tr 'A-Z' 'a-z' | sort -u > "$OUTDIR/gotator_resolved_hosts.txt"
echo "[*] $(wc -l < "$OUTDIR/gotator_resolved_hosts.txt") unique resolved hosts -> $OUTDIR/gotator_resolved_hosts.txt" >&2

if [ -f "$SEED" ]; then
  comm -23 "$OUTDIR/gotator_resolved_hosts.txt" <(sort -u "$SEED") > "$OUTDIR/gotator_new_vs_seed.txt"
  echo "[*] $(wc -l < "$OUTDIR/gotator_new_vs_seed.txt") not already in the seed list -> $OUTDIR/gotator_new_vs_seed.txt" >&2
fi

if command -v httpx >/dev/null 2>&1; then
  echo "[*] fingerprinting with httpx ..." >&2
  httpx -l "$OUTDIR/gotator_resolved_hosts.txt" -sc -cl -title -td -server -location -ip -silent \
        -timeout 5 -retries 1 -threads 200 -o "$OUTDIR/gotator_httpx.txt" || true
  if [ -x "$SCRIPT_DIR/classify_hosts.sh" ]; then
    "$SCRIPT_DIR/classify_hosts.sh" "$OUTDIR/gotator_resolved_hosts.txt" || true
    echo "[*] REVIEW $OUTDIR/gotator_resolved_hosts.txt.classified.tsv — drop the CATCHALL? cluster before treating anything as new" >&2
  fi
fi
