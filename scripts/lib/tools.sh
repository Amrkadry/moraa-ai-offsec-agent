#!/usr/bin/env bash
# lib/tools.sh — tool discovery, sourced by other scripts (not run directly).
#
# WHY: scripts in this repo assume subfinder/amass/httpx/etc. are on PATH, but PATH varies
# across WSL/Kali/macOS boxes and go-installed tools often sit in ~/go/bin which a non-login
# shell (cron, a subprocess spawned without -l) won't have. This searches the common extra
# locations so a script degrades gracefully (skip the step) instead of silently no-op'ing
# a `command -v` check that only ever looked at a half-populated PATH.
#
# Usage (from another script):
#   source "$(dirname "$0")/lib/tools.sh"
#   if p=$(tool_path subfinder); then "$p" -d "$DOMAIN" -silent; else echo "[skip] subfinder missing" >&2; fi
#   tool_exists nuclei && echo "nuclei available"

_MORAA_EXTRA_TOOL_DIRS=(
  "$HOME/go/bin"
  "$HOME/.local/go/bin"
  "$HOME/.local/bin"
  "/usr/local/bin"
  "/usr/local/sbin"
  "/opt/homebrew/bin"
)

# tool_path <name> — prints the resolved absolute path on stdout, returns 1 if not found.
# Checks PATH first (respects any override the caller already set up), then the extra dirs
# above, then one level of /opt/*/bin (covers vendor installs like /opt/metasploit/bin).
tool_path() {
  local name="$1" p d
  if [ -z "$name" ]; then
    echo "tool_path: usage: tool_path <name>" >&2
    return 2
  fi
  p=$(command -v -- "$name" 2>/dev/null) && { printf '%s\n' "$p"; return 0; }
  for d in "${_MORAA_EXTRA_TOOL_DIRS[@]}"; do
    [ -x "$d/$name" ] && { printf '%s\n' "$d/$name"; return 0; }
  done
  for d in /opt/*/bin; do
    [ -x "$d/$name" ] && { printf '%s\n' "$d/$name"; return 0; }
  done
  return 1
}

# tool_exists <name> — boolean check, no output. Use in `if tool_exists X && Y; then`.
tool_exists() {
  tool_path "$1" >/dev/null 2>&1
}

# tool_version <name> [version-flag] — best-effort one-line version string, empty on failure.
# Most Go security tools use -version; a few (dig, curl) use -v/--version.
tool_version() {
  local name="$1" flag="${2:--version}" p out
  p=$(tool_path "$name") || return 1
  out=$("$p" "$flag" 2>&1 | head -n1) || return 1
  printf '%s\n' "$out"
}
