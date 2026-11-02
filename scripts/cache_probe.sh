#!/usr/bin/env bash
# cache_probe.sh — non-destructive web cache poisoning / deception sweep across a list
# of URLs.
#
# WHY: cache poisoning/deception is confirmed by two things at once — an UNKEYED input
# (header or request body) whose value gets reflected into the cached response, AND
# that response actually being served from cache. Hand-probing means ~12 curl calls per
# URL (6 input candidates x warm+verify) plus eyeballing cache headers each time, so
# the class gets skipped. This turns the whole sweep into one command per URL list and
# reports ONLY where reflection and a cache HIT coincide: reflection alone is noise;
# cached reflection is the finding.
#
# NON-DESTRUCTIVE (hard requirement): every probe appends a unique random cache-buster
# query parameter and uses a unique random canary, so a poisoned entry is stored under a
# cache key no real user will request.
#
# That guarantee has a precondition, learned the hard way (acme.example, 2026-09-25): it only
# holds if the query string is part of the cache key. On 4 hosts measured there it was
# NOT — a brand-new random `?zzq=` still returned `Age: 83518` — which makes the buster
# inert, lands every probe on the same key real users are served, and would genuinely
# poison it. So each host now gets a SAFETY PRE-FLIGHT (`query_is_keyed`): two requests
# with two different random query strings; if the second is already a cache HIT, the
# query is unkeyed and the host is REFUSED rather than probed.
# Do not remove the pre-flight, and do not "fix" a skipped host by deleting the check.
#
# Probes per URL (each = warm request + identical verify request):
#   X-Forwarded-Host   X-Forwarded-Scheme   X-Original-URL   X-Rewrite-URL   X-Host
#   + one fat-GET (GET carrying a body — some CDNs fold the body into the key, some
#     apps reflect it)
# Cache-hit detection on the verify response: X-Cache: *HIT*, CF-Cache-Status: HIT,
# or Age >= 1.
#
# Usage:
#   ./cache_probe.sh <url1> [url2 ...]
#   cat urls.txt | ./cache_probe.sh
# Example:
#   ./cache_probe.sh "https://target.com/" "https://target.com/account/menu"

set -euo pipefail

MAX_TIME=15

usage() { awk '/^set -euo/{exit} /^#/{ sub(/^# ?/,""); print }' "$0" | sed '/^$/N;/^\n$/D'; exit 1; }

if [ $# -eq 0 ] && [ -t 0 ]; then
  usage
fi

URLS=()
if [ $# -gt 0 ]; then
  URLS=("$@")
else
  while IFS= read -r u; do
    [ -n "$u" ] && URLS+=("$u")
  done
fi
if [ "${#URLS[@]}" -eq 0 ]; then
  echo "cache_probe: no URLs given" >&2
  exit 1
fi

TMPD="$(mktemp -d)"
trap 'rm -rf "$TMPD"' EXIT

# Unique per probe: epoch-nanos (fallback epoch-secs) + $RANDOM twice + $$ — collision
# odds across a session are negligible, which is what the cache-buster safety needs.
rand_token() { printf 'm%s%s%s' "$(date +%s%N 2>/dev/null || date +%s)" "$RANDOM" "$RANDOM"; }

cache_hit() { # $1 = response headers file
  grep -qiE '^x-cache:.*hit' "$1" && return 0
  grep -qiE '^cf-cache-status:[[:space:]]*hit' "$1" && return 0
  # -i is REQUIRED here, not cosmetic: curl -D writes header names in the case the server
  # sent them, and over HTTP/1.1 a CDN sends canonical `Age:` (capital A). Without -i this
  # arm misses the HIT on exactly those hosts, the pre-flight then declares the query
  # "keyed", and every probe lands on the live cache key a real user is served -- the exact
  # failure this pre-flight exists to prevent. (HTTP/2 lowercases header names on the wire,
  # so h2 hosts matched by luck; h1.1 hosts silently slipped through.) `age: 0`/`Age: 0`
  # still correctly miss -- the [1-9] first digit keeps this from false-positiving.
  grep -qiE '^age:[[:space:]]*[1-9]' "$1" && return 0
  return 1
}

reflected() { # $1 = canary, $2 = body file, $3 = headers file
  # No -i on either grep: canaries are 'm'+digits so there is no case to fold, AND some
  # greps (MSYS/Git-Bash) SIGABRT on -i combined with -F, which silently killed the header
  # check — losing canary-in-Location/Set-Cookie, a classic cache-poisoning signal.
  grep -qF -- "$1" "$2" && return 0
  grep -qF -- "$1" "$3" && return 0
  return 1
}

status_of() { awk 'NR==1{print $2; exit}' "$1" 2>/dev/null | tr -d '\r'; }

# Is the injected header listed in the response's Vary? Then the cache is correctly
# KEYED on it, reflection is not poisoning, and reporting it is a false positive.
# Caught live: config.svc.acme.example reflects Origin into ACAO on a max-age=600 cached
# response, but sends Vary: Origin and CloudFront honours it.
vary_keyed() { # $1 = header name, $2 = headers file
  local v n
  v="$(grep -i '^vary:' "$2" 2>/dev/null | tr 'A-Z' 'a-z' | tr -d ' \r')"
  [ -z "$v" ] && return 1
  n="$(printf '%s' "$1" | tr 'A-Z' 'a-z')"
  printf '%s' "$v" | grep -qF -- "$n"
}

# SAFETY PRE-FLIGHT — the entire non-destructive guarantee rests on this.
# The cache-buster only isolates our probe if the query string is part of the cache
# key. Sometimes it is NOT: measured live on 4 hosts where a brand-new random
# ?zzq= still returned Age: 83518 / 41891 / 2747 / 77. There the buster is inert,
# every probe lands on the SAME cache key a real user is served, and a reflected
# canary WOULD be served to them. Two requests with two DIFFERENT random query
# strings: if the second is already a HIT, the query is unkeyed -> refuse the host.
query_is_keyed() { # $1 = url ; returns 0 = keyed (safe to probe), 1 = unkeyed (unsafe)
  local u1 u2 h
  h="$TMPD/pf"
  case "$1" in
    *\?*) u1="$1&$(rand_token)=1"; u2="$1&$(rand_token)=1" ;;
    *)    u1="$1?$(rand_token)=1"; u2="$1?$(rand_token)=1" ;;
  esac
  : > "$h"; curl -sS --max-time "$MAX_TIME" -o /dev/null -D "$h" "$u1" >/dev/null 2>&1 || true
  : > "$h"; curl -sS --max-time "$MAX_TIME" -o /dev/null -D "$h" "$u2" >/dev/null 2>&1 || true
  cache_hit "$h" && return 1
  return 0
}

FINDINGS=()
TOTAL=0
SKIPPED=()

echo "== cache_probe: ${#URLS[@]} URL(s) x 6 probes (warm+verify each) =="

for url in "${URLS[@]}"; do
  if ! query_is_keyed "$url"; then
    echo "[!] SKIP ${url} — query string is NOT in the cache key (a fresh random param still"
    echo "    returned a cache HIT). The cache-buster is inert here, so probing could poison"
    echo "    the real entry served to users. Refusing. Test this host only under explicit"
    echo "    authorisation, manually, with a unique PATH segment as the buster instead."
    SKIPPED+=("$url")
    continue
  fi
  for probe in xfh xfs xou xru xhost fatget; do
    canary="$(rand_token)"
    # Fresh cache-buster PER PROBE, not per URL. The unkeyed headers under test do not (by
    # definition) change the cache key, so a cb shared across probes would serve probe N the
    # entry cached by probe N-1 — whose canary is different — producing a false negative on
    # exactly the cacheable targets that matter.
    cb="$(rand_token)"
    case "$url" in
      *\?*) base="${url}&cb=${cb}" ;;
      *)    base="${url}?cb=${cb}" ;;
    esac
    TOTAL=$((TOTAL + 1))
    h1="$TMPD/h1" b1="$TMPD/b1" h2="$TMPD/h2" b2="$TMPD/b2"
    : > "$h1"; : > "$b1"; : > "$h2"; : > "$b2"   # curl creates nothing on connect failure

    case "$probe" in
      xfh)    hdr=(-H "X-Forwarded-Host: ${canary}.cache-probe.invalid") ;;
      xfs)    hdr=(-H "X-Forwarded-Scheme: x${canary}") ;;
      xou)    hdr=(-H "X-Original-URL: /${canary}") ;;
      xru)    hdr=(-H "X-Rewrite-URL: /${canary}") ;;
      xhost)  hdr=(-H "X-Host: ${canary}.cache-probe.invalid") ;;
      fatget) hdr=(-H "Content-Type: application/x-www-form-urlencoded") ;;
    esac

    # warm + verify with the IDENTICAL canary and cache-buster, so the verify response
    # is the cached copy of the warm one (Age/HIT on verify == the poisoned variant
    # itself is cacheable).
    if [ "$probe" = fatget ]; then
      curl -sS --max-time "$MAX_TIME" -X GET -d "moraa=${canary}" "${hdr[@]}" \
        -H 'Accept-Encoding: identity' -o "$b1" -D "$h1" "$base" || true
      curl -sS --max-time "$MAX_TIME" -X GET -d "moraa=${canary}" "${hdr[@]}" \
        -H 'Accept-Encoding: identity' -o "$b2" -D "$h2" "$base" || true
    else
      curl -sS --max-time "$MAX_TIME" "${hdr[@]}" \
        -H 'Accept-Encoding: identity' -o "$b1" -D "$h1" "$base" || true
      curl -sS --max-time "$MAX_TIME" "${hdr[@]}" \
        -H 'Accept-Encoding: identity' -o "$b2" -D "$h2" "$base" || true
    fi

    code="$(status_of "$h2")"
    code="${code:-ERR}"
    if cache_hit "$h2"; then cache=HIT; else cache=miss; fi
    # Check BOTH legs: if verify was served from a clean pre-existing entry, the
    # reflection only ever appeared in the warm response.
    if reflected "$canary" "$b2" "$h2" || reflected "$canary" "$b1" "$h1"; then refl=yes; else refl=no; fi

    # The header this probe injects — needed for the Vary check.
    case "$probe" in
      xfh)    inj_hdr="x-forwarded-host" ;;
      xfs)    inj_hdr="x-forwarded-scheme" ;;
      xou)    inj_hdr="x-original-url" ;;
      xru)    inj_hdr="x-rewrite-url" ;;
      xhost)  inj_hdr="x-host" ;;
      fatget) inj_hdr="" ;;
    esac

    keyed=no
    if [ -n "$inj_hdr" ] && vary_keyed "$inj_hdr" "$h2"; then keyed=yes; fi

    note=""
    # GET-with-body is rejected at the edge by CloudFront and similar CDNs (403 on
    # every host measured). That is the CDN refusing the request shape, NOT evidence
    # the origin is safe — label it inconclusive rather than banking a clean negative.
    if [ "$probe" = fatget ] && [ "$code" = "403" ]; then note="  (fat-GET rejected by CDN — INCONCLUSIVE, not a negative)"; fi
    if [ "$keyed" = yes ]; then note="  (Vary: ${inj_hdr} present — cache is correctly KEYED, not poisonable)"; fi

    echo "[*] ${url}  [${probe}]  status=${code}  cache=${cache}  reflected=${refl}${note}"

    if [ "$cache" = HIT ] && [ "$refl" = yes ] && [ "$keyed" = no ]; then
      FINDINGS+=("${probe}|${url}|${canary}|${base}")
    fi
  done
done

if [ "${#SKIPPED[@]}" -gt 0 ]; then
  echo
  echo "=== SKIPPED ${#SKIPPED[@]} host(s) as unsafe to probe (query string not in cache key) ==="
  for s in "${SKIPPED[@]}"; do echo "  $s"; done
fi

echo
if [ "${#FINDINGS[@]}" -gt 0 ]; then
  echo "=== FINDINGS: canary reflected AND served from cache (${#FINDINGS[@]}) — verify + report ==="
  for f in "${FINDINGS[@]}"; do
    IFS='|' read -r probe url canary base <<< "$f"
    case "$probe" in
      xfh)    h="X-Forwarded-Host: ${canary}.cache-probe.invalid" ;;
      xfs)    h="X-Forwarded-Scheme: x${canary}" ;;
      xou)    h="X-Original-URL: /${canary}" ;;
      xru)    h="X-Rewrite-URL: /${canary}" ;;
      xhost)  h="X-Host: ${canary}.cache-probe.invalid" ;;
      fatget) h="GET body: moraa=${canary}" ;;
    esac
    echo "  ${url}"
    echo "    injected: ${h}"
    if [ "$probe" = fatget ]; then
      echo "    reproduce: curl -sk -D- -X GET -d 'moraa=${canary}' '${base}'   # while TTL lives"
    else
      echo "    reproduce: curl -sk -D- -H '${h}' '${base}'   # while TTL lives"
    fi
  done
else
  echo "=== no cached reflection across ${TOTAL} probes — nothing reportable from this surface ==="
fi
