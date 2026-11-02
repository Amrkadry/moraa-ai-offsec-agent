#!/usr/bin/env bash
# lib/config.sh — API key / config lookup, sourced by other scripts (not run directly).
#
# WHY: several sources (chaos, github-subdomains, Shodan/FOFA pivots, SecurityTrails/VirusTotal
# enrichment) need an API key. Keys must never be hardcoded or printed. Environment variables win;
# ~/.moraa/config.json is a local, gitignored-by-convention fallback for keys you don't want to
# export in every shell. Presence is reportable (doctor.sh); values never are.
#
# Usage:
#   source "$(dirname "$0")/lib/tools.sh"   # optional, not required by config.sh itself
#   source "$(dirname "$0")/lib/config.sh"
#   key=$(moraa_config_get CHAOS_API_KEY) || echo "[skip] no chaos key" >&2
#   moraa_config_has SHODAN_API_KEY && echo "shodan configured"

MORAA_CONFIG_FILE="${MORAA_CONFIG_FILE:-$HOME/.moraa/config.json}"

# _moraa_config_json_get <key> — best-effort flat-key lookup in the config JSON without
# requiring jq (sandboxed engagement boxes routinely lack it). Only handles a flat
# {"KEY": "value", ...} object, which is all this file is meant to hold.
_moraa_config_json_get() {
  local key="$1"
  [ -f "$MORAA_CONFIG_FILE" ] || return 1
  python3 - "$MORAA_CONFIG_FILE" "$key" <<'PYEOF' 2>/dev/null
import json, sys
path, key = sys.argv[1], sys.argv[2]
try:
    with open(path) as f:
        data = json.load(f)
except Exception:
    sys.exit(1)
val = data.get(key)
if not val:
    sys.exit(1)
print(val)
PYEOF
}

# moraa_config_get <ENV_VAR_NAME> — prints the key on stdout, returns 1 if unset anywhere.
# Precedence: environment variable > ~/.moraa/config.json entry of the same name.
moraa_config_get() {
  local name="$1" val
  if [ -z "$name" ]; then
    echo "moraa_config_get: usage: moraa_config_get <ENV_VAR_NAME>" >&2
    return 2
  fi
  val="${!name:-}"
  if [ -n "$val" ]; then
    printf '%s\n' "$val"
    return 0
  fi
  _moraa_config_json_get "$name"
}

# moraa_config_has <ENV_VAR_NAME> — boolean presence check, no value ever printed.
moraa_config_has() {
  moraa_config_get "$1" >/dev/null 2>&1
}

# Known optional API keys this repo's scripts can use, for doctor.sh to enumerate.
# Add new ones here (and to doctor.sh's table) as scripts start consuming them.
MORAA_KNOWN_API_KEYS=(
  CHAOS_API_KEY
  GH_TOKEN
  SHODAN_API_KEY
  SECURITYTRAILS_API_KEY
  VIRUSTOTAL_API_KEY
  CENSYS_API_ID
  CENSYS_API_SECRET
  FOFA_EMAIL
  FOFA_API_KEY
)
