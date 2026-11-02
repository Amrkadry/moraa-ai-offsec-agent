#!/usr/bin/env bash
# doctor.sh — recon environment diagnostic. Run this first on a new box/WSL distro before
# trusting recon.md's commands to work; every listed tool is one recon.md or scripts/
# assumes exists somewhere in its pipeline.
#
# Usage:
#   scripts/doctor.sh            # human-readable report
#   scripts/doctor.sh --json     # machine-readable, for an agent to branch on
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
# shellcheck source=lib/tools.sh
source "$SCRIPT_DIR/lib/tools.sh"
# shellcheck source=lib/config.sh
source "$SCRIPT_DIR/lib/config.sh"

JSON=0
[ "${1:-}" = "--json" ] && JSON=1

# name, required(1/0), version-flag  — required tools missing = doctor exits non-zero.
# version-flag is empty string when the tool has no sane single-line --version output.
TOOL_TABLE="
subfinder 1 -version
dnsx 1 -version
httpx 1 -version
anew 0
dig 1 -v
curl 1 --version
python3 1 --version
ffuf 0 -V
gotator 0
amass 0 -version
assetfinder 0
findomain 0 --version
chaos 0 -version
nuclei 0 -version
katana 0 -version
gau 0
theHarvester 0
whatweb 0 --version
wafw00f 0 --version
puredns 0
naabu 0 -version
unfurl 0 --version
gf 0
trufflehog 0 --version
gitleaks 0 version
feroxbuster 0 --version
dnsgen 0
git-dumper 0
meg 0
"

declare -a TOOL_ROWS=()
MISSING_REQUIRED=0

while read -r name required vflag; do
  [ -z "$name" ] && continue
  if p=$(tool_path "$name"); then
    if [ -n "${vflag:-}" ]; then
      ver=$(tool_version "$name" "$vflag" 2>/dev/null || true)
    else
      ver=""
    fi
    TOOL_ROWS+=("OK|$name|$p|$ver")
  else
    if [ "$required" = "1" ]; then
      TOOL_ROWS+=("MISSING|$name||")
      MISSING_REQUIRED=1
    else
      TOOL_ROWS+=("WARN|$name||")
    fi
  fi
done <<EOF
$TOOL_TABLE
EOF

declare -a KEY_ROWS=()
for key in "${MORAA_KNOWN_API_KEYS[@]}"; do
  if moraa_config_has "$key"; then
    KEY_ROWS+=("CONFIGURED|$key")
  else
    KEY_ROWS+=("NOT_CONFIGURED|$key")
  fi
done

# Network / DNS reachability — cheap, bounded timeout, never hangs the report.
DNS_OK=0
NET_OK=0
if command -v timeout >/dev/null 2>&1; then
  timeout 5 dig +short example.com >/dev/null 2>&1 && DNS_OK=1
  timeout 5 curl -sf -o /dev/null https://example.com >/dev/null 2>&1 && NET_OK=1
else
  dig +short example.com >/dev/null 2>&1 && DNS_OK=1
  curl -sf -o /dev/null https://example.com >/dev/null 2>&1 && NET_OK=1
fi

# Writable output dir check — mirrors what a recon script will try to do (mkdir -p recon/).
OUT_TEST_DIR="${MORAA_TEST_OUTPUT_DIR:-recon}"
WRITABLE=0
if mkdir -p "$OUT_TEST_DIR" 2>/dev/null && [ -w "$OUT_TEST_DIR" ]; then
  WRITABLE=1
fi

if [ "$JSON" = "1" ]; then
  TOOL_ROWS_TXT=$(printf '%s\n' "${TOOL_ROWS[@]}")
  KEY_ROWS_TXT=$(printf '%s\n' "${KEY_ROWS[@]}")
  export TOOL_ROWS_TXT KEY_ROWS_TXT
  python3 - "$MISSING_REQUIRED" "$DNS_OK" "$NET_OK" "$WRITABLE" "$OUT_TEST_DIR" <<'PYEOF'
import json, os, sys
missing_required, dns_ok, net_ok, writable, out_dir = sys.argv[1:6]

tools = []
for line in os.environ.get("TOOL_ROWS_TXT", "").splitlines():
    if not line.strip():
        continue
    parts = (line.split("|", 3) + ["", "", "", ""])[:4]
    status, name, path, ver = parts
    tools.append({"name": name, "status": status, "path": path or None, "version": ver or None})

keys = []
for line in os.environ.get("KEY_ROWS_TXT", "").splitlines():
    if not line.strip():
        continue
    status, name = line.split("|", 1)
    keys.append({"name": name, "status": status})

result = {
    "tools": tools,
    "api_keys": keys,
    "network": {"dns_ok": bool(int(dns_ok)), "internet_ok": bool(int(net_ok))},
    "output_dir": {"path": out_dir, "writable": bool(int(writable))},
    "missing_required_tools": bool(int(missing_required)),
}
print(json.dumps(result, indent=2))
PYEOF
  exit "$MISSING_REQUIRED"
fi

echo "Recon Environment"
echo ""
for row in "${TOOL_ROWS[@]}"; do
  IFS='|' read -r status name path ver <<< "$row"
  case "$status" in
    OK)      printf "[OK]      %-14s %s %s\n" "$name" "$path" "${ver:+($ver)}" ;;
    WARN)    printf "[WARN]    %-14s not found (optional)\n" "$name" ;;
    MISSING) printf "[MISSING] %-14s not found (REQUIRED)\n" "$name" ;;
  esac
done

echo ""
echo "API Configuration"
echo ""
for row in "${KEY_ROWS[@]}"; do
  IFS='|' read -r status name <<< "$row"
  if [ "$status" = "CONFIGURED" ]; then
    printf "%-24s [CONFIGURED]\n" "$name"
  else
    printf "%-24s [NOT CONFIGURED]\n" "$name"
  fi
done

echo ""
echo "Network"
echo ""
[ "$DNS_OK" = "1" ] && echo "[OK]   DNS resolution (dig example.com)" || echo "[FAIL] DNS resolution (dig example.com)"
[ "$NET_OK" = "1" ] && echo "[OK]   Internet reachability (curl https://example.com)" || echo "[FAIL] Internet reachability"
[ "$WRITABLE" = "1" ] && echo "[OK]   Output dir writable ($OUT_TEST_DIR)" || echo "[FAIL] Output dir NOT writable ($OUT_TEST_DIR)"

echo ""
if [ "$MISSING_REQUIRED" = "1" ]; then
  echo "[!] One or more REQUIRED tools are missing — install before relying on recon.md's pipelines."
else
  echo "[OK] All required tools present."
fi

exit "$MISSING_REQUIRED"
