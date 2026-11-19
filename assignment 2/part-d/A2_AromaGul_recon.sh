#!/usr/bin/env bash
# =============================================================================
#  A2 Part D - Attack-surface inventory recon pipeline (Part B scanner is A2_AromaGul_scan.sh)
#  Target used for the submission: OWASP Juice Shop 20.4.0-SNAPSHOT, running as
#  a Docker container in my own Kali lab (http://localhost:3000).
#
#  Usage:
#     ./A2_AromaGul_recon.sh <base-url> [output-dir]
#  Examples:
#     ./A2_AromaGul_recon.sh http://localhost:3000
#     ./A2_AromaGul_recon.sh https://staging.example.com out-example
#
#  Works against a different target with no edits:
#   - If the host is a DNS name, stage 1 enumerates subdomains passively
#     (crt.sh + subfinder if installed) and resolves/probes them.
#   - If the host is localhost / an IP, stage 1 records the listener instead.
#   Stages 2-8 run against the base URL you pass in.
#
#  ONLY run this against systems you own or are explicitly authorised to test.
#  Stages 2, 4 and 6 send active traffic (full port scan, ~4.7k-word directory
#  brute force, one request per discovered path).
#
#  Requirements (Kali): nmap whatweb ffuf jq curl seclists httpx-toolkit
#     sudo apt install -y nmap whatweb ffuf jq curl seclists httpx-toolkit
#  Optional (domain targets): subfinder, dnsutils (dig)
# =============================================================================
set -uo pipefail

TARGET="${1:-}"
OUT="${2:-out}"
WORDLIST="${WORDLIST:-/usr/share/seclists/Discovery/Web-Content/common.txt}"
THREADS="${THREADS:-40}"

if [[ -z "$TARGET" ]]; then
  echo "usage: $0 <base-url> [output-dir]   e.g. $0 http://localhost:3000" >&2
  exit 1
fi
TARGET="${TARGET%/}"                                   # strip trailing slash
HOSTPORT="$(echo "$TARGET" | sed -E 's#^[a-z]+://##; s#/.*$##')"
HOST="${HOSTPORT%%:*}"
SCHEME="${TARGET%%://*}"
PORT="$(echo "$HOSTPORT" | grep -oE ':[0-9]+$' | tr -d ':')"
[[ -z "$PORT" ]] && { [[ "$SCHEME" == "https" ]] && PORT=443 || PORT=80; }

# --- scope gate: make the operator confirm authorisation once ---------------
if [[ "${I_AM_AUTHORISED:-}" != "yes" ]]; then
  read -r -p "[?] Do you own or have written permission to test $HOST ? (yes/no) " ans
  [[ "$ans" == "yes" ]] || { echo "[-] Aborting: not authorised."; exit 1; }
fi

# --- tool check --------------------------------------------------------------
for t in curl jq nmap whatweb ffuf; do
  command -v "$t" >/dev/null || { echo "[-] missing tool: $t"; exit 1; }
done
HTTPX="$(command -v httpx-toolkit || command -v httpx || true)"
[[ -f "$WORDLIST" ]] || { echo "[-] wordlist not found: $WORDLIST"; exit 1; }

mkdir -p "$OUT"
log() { printf '\n[+] %s\n' "$*"; }
is_ip_or_local() { [[ "$1" == "localhost" || "$1" =~ ^[0-9.]+$ || "$1" =~ : ]]; }

# Resolve to an IP for nmap (getent works for both names and localhost)
IP="$(getent ahostsv4 "$HOST" | awk 'NR==1{print $1}')"
[[ -z "$IP" ]] && IP="$HOST"
echo "target=$TARGET host=$HOST ip=$IP port=$PORT" | tee "$OUT/00_target.txt"

# =============================================================================
# STAGE 1 - Asset discovery at the host level
# =============================================================================
if is_ip_or_local "$HOST"; then
  log "Stage 1: local/IP target - recording listeners and container info"
  # Which process owns each listening socket (needs sudo for process names)
  sudo ss -ltnp 2>/dev/null | tee "$OUT/01b_listeners.txt"
  # If the app is a Docker container, record its image and internal IP
  if command -v docker >/dev/null; then
    sudo docker ps --format '{{.Names}}\t{{.Image}}\t{{.Ports}}' 2>/dev/null | tee "$OUT/01c_containers.txt"
  fi
  echo "$HOST" > "$OUT/01_hosts.txt"
else
  log "Stage 1: passive subdomain enumeration for $HOST"
  # 1a Certificate-transparency logs (no traffic to the target)
  curl -s -m 60 "https://crt.sh/?q=%25.${HOST}&output=json" \
    | jq -r '.[].name_value' 2>/dev/null | tr 'A-Z' 'a-z' | sed 's/^\*\.//' > "$OUT/01a_crtsh.txt"
  # 1b subfinder passive sources, if installed
  command -v subfinder >/dev/null && subfinder -silent -d "$HOST" > "$OUT/01a_subfinder.txt"
  { cat "$OUT"/01a_*.txt 2>/dev/null; echo "$HOST"; } | sort -u > "$OUT/01_hosts.txt"
  # 1c DNS resolution: keep only names that resolve
  while read -r h; do
    ips="$(getent ahostsv4 "$h" | awk '{print $1}' | sort -u | paste -sd, -)"
    [[ -n "$ips" ]] && printf '%s\t%s\n' "$h" "$ips"
  done < "$OUT/01_hosts.txt" | tee "$OUT/01d_resolved.tsv"
  # 1d Live HTTP(S) services with title, status, tech and IP
  if [[ -n "$HTTPX" ]]; then
    cut -f1 "$OUT/01d_resolved.tsv" | "$HTTPX" -silent -sc -title -td -ip -cdn \
      -o "$OUT/01e_httpx.txt"
  fi
fi

# =============================================================================
# STAGE 2 - Ports and services
# =============================================================================
log "Stage 2a: full TCP port scan of $IP"
sudo nmap -p- --min-rate 2000 -T4 -oN "$OUT/01_ports_all.txt" "$IP"
OPEN="$(grep -E '^[0-9]+/tcp +open' "$OUT/01_ports_all.txt" | cut -d/ -f1 | paste -sd, -)"
log "Stage 2b: service/version + default scripts on: ${OPEN:-$PORT}"
sudo nmap -sV -sC -p "${OPEN:-$PORT}" -oN "$OUT/02_services.txt" "$IP"

# =============================================================================
# STAGE 3 - Tech fingerprint and security headers
# =============================================================================
log "Stage 3: fingerprint"
whatweb -a 3 "$TARGET" | tee "$OUT/03_whatweb.txt"
curl -s -D - -o /dev/null "$TARGET/" | tee "$OUT/04_headers.txt"
# CORS pre-flight: which methods does the server allow cross-origin?
curl -s -D - -o /dev/null -X OPTIONS -H 'Origin: https://evil.example' \
  -H 'Access-Control-Request-Method: DELETE' "$TARGET/" | tee "$OUT/04b_cors_preflight.txt"
# Which common security headers are missing?
for h in content-security-policy strict-transport-security x-frame-options \
         x-content-type-options referrer-policy permissions-policy; do
  grep -qi "^$h:" "$OUT/04_headers.txt" && echo "present  $h" || echo "MISSING  $h"
done | tee "$OUT/04c_header_audit.txt"

# =============================================================================
# STAGE 4 - Content discovery
# =============================================================================
log "Stage 4a: robots.txt / security.txt"
curl -s "$TARGET/robots.txt" | tee "$OUT/05_robots.txt"; echo
curl -s "$TARGET/.well-known/security.txt" | tee "$OUT/06_security_txt.txt"; echo

log "Stage 4b: directory brute force"
# SPAs answer every unknown path with the index page. Measure that size with a
# random path and filter it out so only real routes are reported.
RAND="$(head -c 12 /dev/urandom | od -An -tx1 | tr -d ' \n')"
FS="$(curl -s -o /dev/null -w '%{size_download}' "$TARGET/$RAND")"
echo "catch-all response size = $FS (filtered)"
ffuf -s -u "$TARGET/FUZZ" -w "$WORDLIST" -t "$THREADS" \
     -mc 200,204,301,302,307,401,403,405,500 -fs "$FS" \
     -o "$OUT/07_ffuf_root.json" -of json >/dev/null
jq -r '.results[] | "\(.status)\t\(.length)\t/\(.input.FUZZ)"' "$OUT/07_ffuf_root.json" \
  | tee "$OUT/07_ffuf_root.txt"

log "Stage 4c: JavaScript bundle mining"
# Download every .js referenced by the index page, then any lazy-loaded chunks
: > "$OUT/08_bundle.js"
for js in $(curl -s "$TARGET/" | grep -oE '[a-zA-Z0-9._-]+\.js' | sort -u); do
  curl -s "$TARGET/$js" >> "$OUT/08_bundle.js"; echo >> "$OUT/08_bundle.js"
done
for c in $(grep -oE 'chunk-[A-Za-z0-9]+\.js' "$OUT/08_bundle.js" | sort -u); do
  curl -s "$TARGET/$c" >> "$OUT/08_bundle.js"; echo >> "$OUT/08_bundle.js"
done
wc -c "$OUT/08_bundle.js"
# Server-side API paths referenced by the front end
grep -oE '/(api|rest|b2b|graphql|v[0-9]+|ftp|socket\.io|metrics|snippets|redirect|profile|file-upload|upload|video|promotion|dataerasure|encryptionkeys|support|api-docs|swagger|admin|assets/public|\.well-known)[A-Za-z0-9_./?=-]*' \
  "$OUT/08_bundle.js" | sort -u | tee "$OUT/08_js_endpoints.txt"
# Client-side (Angular/React router) routes
grep -oE "path:[\"'\`][^\"'\`]*" "$OUT/08_bundle.js" | cut -c7- | sort -u \
  | tee "$OUT/09_spa_routes.txt"

# =============================================================================
# STAGE 5 - Build one candidate list and probe every entry
# =============================================================================
log "Stage 5: probe all candidates"
# Conventional paths for a Node/Express stack that wordlists often miss
EXTRA_PATHS=( /api-docs /api-docs/swagger.json /swagger.json /metrics /b2b/v2/orders
  /snippets /encryptionkeys /support/logs /rest/admin/application-version
  /rest/admin/application-configuration /assets/public/images/uploads
  /.well-known/csaf/provider-metadata.json /ftp/quarantine
  '/socket.io/?EIO=4&transport=polling' )
{ cat "$OUT/08_js_endpoints.txt"
  jq -r '.results[].input.FUZZ' "$OUT/07_ffuf_root.json" | sed 's#^#/#'
  printf '%s\n' "${EXTRA_PATHS[@]}"
} | grep -vE '^/api\.|geoip2|socket\.io/docs|\?key=|\?to=|\?current=|\?email=' \
  | sort -u > "$OUT/12_candidates.txt"
wc -l "$OUT/12_candidates.txt"
while read -r p; do
  curl -s -o /dev/null -m 10 \
    -w "%{http_code}\t%{size_download}\t%{content_type}\t$p\n" "$TARGET$p"
done < "$OUT/12_candidates.txt" | tee "$OUT/13_probe.tsv"
# Mark responses equal to the SPA catch-all size: not real server endpoints
awk -F'\t' -v fs="$FS" '$2==fs{print "SPA-fallback\t"$4}' "$OUT/13_probe.tsv" \
  | tee "$OUT/13b_spa_fallback.txt"

# =============================================================================
# STAGE 6 - Look inside the interesting ones
# =============================================================================
log "Stage 6: directory listings, error pages, versions"
# Any path whose body looks like a directory listing
grep -P '^200\t' "$OUT/13_probe.tsv" | cut -f4 | while read -r p; do
  body="$(curl -s -m 10 "$TARGET$p")"
  if echo "$body" | grep -qiE 'listing directory|index of /'; then
    echo "== $p"; echo "$body" | grep -oE 'href="[^"]+"' | sed 's/href=//'
  fi
done | tee "$OUT/10_dir_listings.txt"
# Does the generic 500 page disclose an error message / stack trace?
curl -s "$TARGET/rest" > "$OUT/11_error_page.html"
grep -oE '<title>[^<]*' "$OUT/11_error_page.html" | tee "$OUT/11_error_summary.txt"
sed 's/&nbsp;/ /g; s/<[^>]*>//g' "$OUT/11_error_page.html" | grep -E '^\s*at ' | head -5 \
  | tee -a "$OUT/11_error_summary.txt"
# Version disclosure
curl -s "$TARGET/rest/admin/application-version" | tee "$OUT/14_versions.txt"; echo
curl -s "$TARGET/metrics" | grep -m3 'version_info' | tee -a "$OUT/14_versions.txt"

# =============================================================================
# STAGE 7 - Auth fingerprint
# =============================================================================
log "Stage 7: which endpoints demand authentication"
awk -F'\t' '$1==401||$1==403{print $1"\t"$4}' "$OUT/13_probe.tsv" | tee "$OUT/15_auth_required.txt"
awk -F'\t' '$1==200 && $3 ~ /json/ {print $1"\t"$2"\t"$4}' "$OUT/13_probe.tsv" \
  | tee "$OUT/16_unauth_json.txt"
# What does the server say for an anonymous identity check?
curl -s "$TARGET/rest/user/whoami" | tee "$OUT/17_whoami_anon.txt"; echo

# =============================================================================
# STAGE 8 - Summary
# =============================================================================
log "Stage 8: summary"
{
  echo "Target           : $TARGET ($IP)"
  echo "Open ports       : ${OPEN:-none}"
  echo "ffuf hits        : $(wc -l < "$OUT/07_ffuf_root.txt")"
  echo "JS endpoints     : $(wc -l < "$OUT/08_js_endpoints.txt")"
  echo "SPA routes       : $(wc -l < "$OUT/09_spa_routes.txt")"
  echo "Probed candidates: $(wc -l < "$OUT/12_candidates.txt")"
  echo "401/403 (authed) : $(wc -l < "$OUT/15_auth_required.txt")"
  echo "Unauth JSON 200  : $(wc -l < "$OUT/16_unauth_json.txt")"
} | tee "$OUT/99_summary.txt"
echo "[+] Done. All evidence is in $OUT/"
