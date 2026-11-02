#!/usr/bin/env bash
# find_asn_netblocks.sh — find a company's own dedicated ASN/netblock via ARIN,
# distinguishing it from shared cloud IP space.
#
# Why this exists: on a cloud-hosted company, every discoverable hostname usually
# resolves into shared AWS/CloudFront/Shopify/Cloudflare IP space, which tells you
# nothing about "does this org even have its own network." This script finds the
# ACTUAL dedicated allocation (if any) so you know whether an ASN/CIDR-based
# enumeration angle is worth pursuing at all, and whether it's in your stated scope
# (dedicated ranges are very often the corporate office/VPN network, NOT the
# customer-facing product estate — confirm scope before touching it; see the
# acme.example r23 pass, 2026-09-18, which found AS27625/192.76.255.0/24 = the vendor's own
# San Jose office network, explicitly out of a domain-scoped bug bounty).
#
# Usage:
#   ./find_asn_netblocks.sh "<org name search term>"
#   ./find_asn_netblocks.sh "the vendor*"
#
# Requires: curl, python3. No API key needed (ARIN's REST/whois-rws API is public).
set -euo pipefail

TERM="${1:?usage: find_asn_netblocks.sh \"<org name search term>\"}"

echo "[*] searching ARIN orgs matching: $TERM" >&2
ORGS_JSON=$(curl -sS "https://whois.arin.net/rest/orgs;name=${TERM// /%20}" -H "Accept: application/json")

echo "$ORGS_JSON" | python3 -c '
import json, sys
d = json.load(sys.stdin)
refs = d.get("orgs", {}).get("orgRef", [])
refs = [refs] if isinstance(refs, dict) else refs
if not refs:
    print("no matching orgs found", file=sys.stderr)
    sys.exit(1)
for r in refs:
    print(f"{r[\"@handle\"]}\t{r[\"@name\"]}")
' | tee /tmp/find_asn_orgs.tsv

echo "" >&2
echo "[*] pulling nets + ASNs for each org handle" >&2
while IFS=$'\t' read -r handle name; do
  echo "=== $handle ($name) ===" >&2
  nets=$(curl -sS "https://whois.arin.net/rest/org/$handle/nets" -H "Accept: application/json")
  echo "$nets" | python3 -c '
import json, sys
try:
    d = json.load(sys.stdin)
except Exception:
    sys.exit(0)
nets = d.get("nets", {}).get("netRef", [])
nets = [nets] if isinstance(nets, dict) else nets
for n in nets:
    url = n["$"]
    detail = json.loads(__import__("urllib.request", fromlist=["urlopen"]).urlopen(
        __import__("urllib.request").Request(url, headers={"Accept":"application/json"})).read())["net"]
    name = detail.get("name", {}).get("$", "?")
    start = detail.get("startAddress", {}).get("$", "?")
    end = detail.get("endAddress", {}).get("$", "?")
    blk = detail.get("netBlocks", {}).get("netBlock", {})
    cidr = blk.get("cidrLength", {}).get("$", "?") if isinstance(blk, dict) else "?"
    kind = blk.get("description", {}).get("$", "?") if isinstance(blk, dict) else "?"
    print(f"  NET  {name:20s} {start}/{cidr}  ({kind})")
' 2>/dev/null || true

  asns=$(curl -sS "https://whois.arin.net/rest/org/$handle/asns" -H "Accept: application/json")
  echo "$asns" | python3 -c '
import json, sys
try:
    d = json.load(sys.stdin)
except Exception:
    sys.exit(0)
a = d.get("asns", {}).get("asnRef", [])
a = [a] if isinstance(a, dict) else a
for x in a:
    print(f"  ASN  {x[\"@handle\"]}  {x[\"@name\"]}")
' 2>/dev/null || true
done < /tmp/find_asn_orgs.tsv

echo "" >&2
echo "[!] REMINDER: a dedicated netblock is very often the corporate/office network," >&2
echo "    not customer-facing product infra. Confirm it's actually in scope before" >&2
echo "    running any port scan or reverse-DNS sweep against it." >&2
