#!/usr/bin/env bash
set -euo pipefail

# Simple HTTP checker:
# - Use a single URL (-u) OR a targets file (-t)
# - Checks both HTTPS and HTTP separately (no -L for status)
# - Any 2xx/3xx on either = reachable
# - Follows redirects only when fetching body (for parked-page detection)
# - Writes ONE results file in the CURRENT DIRECTORY:
#       is-alive-results.txt  (tab-separated text)  OR
#       is-alive-results.csv  (comma-separated CSV)
#
# Columns:
#   url,https,http,status
#
# Status values (4th column) can be:
#   ALIVE              - reachable, not parked
#   PARKED             - looks like a domain reseller / parked page
#   DEAD               - no 2xx/3xx on HTTPS or HTTP
#   REDIRECT-NO-BODY   - redirect, but couldn't fetch final body
#   ERROR-NO-BODY      - 2xx/3xx but no body (weird / error)
#
# Extra:
#   -s STATUS   If provided, also create a second file containing only URLs
#               whose status matches STATUS, one per line.
#               This is ideal as gowitness input, e.g. -s ALIVE
#
# Usage:
#   ./is-alive.sh -u example.com
#   ./is-alive.sh -t targets.txt
#   ./is-alive.sh -t targets.txt -o csv
#   ./is-alive.sh -t targets.txt -o csv -s ALIVE
#   ./is-alive.sh                      # uses ./targets.txt if present

TARGETS_FILE=""
SINGLE_URL=""
DELAY="0.2"
OUTPUT_MODE="txt"  # txt or csv
STATUS_FILTER=""   # if set via -s, we output a second file with these only

BROWSER_UA="Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 \
 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36"

TOTAL_TARGETS=0
CURRENT_INDEX=0

usage() {
  cat <<EOF
Usage: $0 [-u url] [-t targets.txt] [-d delay_seconds] [-o txt|csv] [-s STATUS]

Options:
  -u URL      Single URL/domain to check (e.g. example.com or https://example.com)
  -t FILE     Targets file (one host/URL per line)
  -d SECONDS  Delay between requests (default: 0.2)
  -o MODE     Output format: 'txt' (default) or 'csv'
  -s STATUS   Also write a second file containing only URLs with this STATUS
              (e.g. ALIVE, PARKED, DEAD, REDIRECT-NO-BODY, ERROR-NO-BODY)
  -h          Show this help

If neither -u nor -t is given but a 'targets.txt' exists in the current
directory, it will be used as the targets file.

Output:
  is-alive-results.txt  (tab-separated, if -o txt)
  is-alive-results.csv  (comma-separated, if -o csv)

If -s STATUS is given, also output:
  is-alive-<status>.txt  (one URL per line, e.g. is-alive-ALIVE.txt)

Columns in results file:
  url,https,http,status
EOF
}

# Parse options
while getopts ":u:t:d:o:s:h" opt; do
  case "$opt" in
    u)
      SINGLE_URL="$OPTARG"
      ;;
    t)
      TARGETS_FILE="$OPTARG"
      ;;
    d)
      DELAY="$OPTARG"
      ;;
    o)
      OUTPUT_MODE="$OPTARG"
      ;;
    s)
      STATUS_FILTER="$OPTARG"
      ;;
    h)
      usage
      exit 0
      ;;
    *)
      usage
      exit 1
      ;;
  esac
done

# Validate output mode
if [[ "$OUTPUT_MODE" != "txt" && "$OUTPUT_MODE" != "csv" ]]; then
  echo "Error: -o must be 'txt' or 'csv' (got '$OUTPUT_MODE')" >&2
  exit 1
fi

# Validate -u / -t combination
if [ -n "$SINGLE_URL" ] && [ -n "$TARGETS_FILE" ]; then
  echo "Error: please use either -u (single URL) OR -t (targets file), not both." >&2
  exit 1
fi

# If neither provided, fall back to ./targets.txt if it exists
if [ -z "$SINGLE_URL" ] && [ -z "$TARGETS_FILE" ]; then
  if [ -f "targets.txt" ]; then
    TARGETS_FILE="targets.txt"
  else
    echo "Error: you must specify -u URL or -t targets_file (or create ./targets.txt)." >&2
    usage
    exit 1
  fi
fi

# If using a file, make sure it exists
if [ -n "$TARGETS_FILE" ] && [ ! -f "$TARGETS_FILE" ]; then
  echo "Error: $TARGETS_FILE not found" >&2
  exit 1
fi

if [ -n "$SINGLE_URL" ]; then
  echo "[*] Mode: single URL"
  echo "[*] URL:  $SINGLE_URL"
  TOTAL_TARGETS=1
else
  echo "[*] Mode: targets file"
  echo "[*] Using targets file: $TARGETS_FILE"
  # Count non-empty, non-comment lines for progress
  TOTAL_TARGETS=$(grep -Ev '^\s*($|#)' "$TARGETS_FILE" | wc -l | tr -d ' ')
fi

echo "[*] Delay between requests: $DELAY seconds"
echo "[*] Output files will be created in: $PWD"

# Decide output filename + delimiter
results_base="$PWD/is-alive-results"
if [ "$OUTPUT_MODE" = "csv" ]; then
  results_file="${results_base}.csv"
  delim=","
else
  results_file="${results_base}.txt"
  delim=$'\t'
fi

# Truncate / create results file and write header
: > "$results_file"
printf "url${delim}https${delim}http${delim}status\n" >> "$results_file"

# If STATUS_FILTER is set, prepare the filtered list file
filtered_targets_file=""
if [ -n "$STATUS_FILTER" ]; then
  filtered_targets_file="$PWD/is-alive-${STATUS_FILTER}.txt"
  : > "$filtered_targets_file"
  echo "[*] Will also write URLs with status '$STATUS_FILTER' to: $filtered_targets_file"
fi

# Normalise: strip protocol, trailing slash, and any path
normalise() {
  local d="$1"
  d="${d#http://}"
  d="${d#https://}"
  # strip path after first slash
  d="${d%%/*}"
  # strip trailing slash if any left
  d="${d%/}"
  echo "$d"
}

# Fetch a small snippet of the page body (for parked-page detection)
# We follow redirects here (-L) to inspect the final content.
get_body_snippet() {
  local host="$1"
  local snippet=""

  # Try HTTPS first
  snippet=$(curl -ksS -L \
    --user-agent "$BROWSER_UA" \
    --max-time 10 --connect-timeout 5 "https://$host" | head -c 20000 || true)

  if [ -z "$snippet" ]; then
    # Try HTTP as fallback
    snippet=$(curl -ksS -L \
      --user-agent "$BROWSER_UA" \
      --max-time 10 --connect-timeout 5 "http://$host" | head -c 20000 || true)
  fi

  echo "$snippet"
}

# Heuristic parked / "domain for sale" detector
is_parked_page() {
  local body="$1"

  # Lower-case copy for generic text matches
  local lower
  lower=$(printf "%s" "$body" | tr '[:upper:]' '[:lower:]')

  # --- Generic parked / for-sale wording ---
  if grep -qE "this domain is for sale|buy this domain|domain for sale|is parked free|domain parked|parkingcrew|sedo domain parking|afternic|uniregistry|undeveloped" <<< "$lower"; then
    return 0
  fi

  if grep -qE "godaddy.com.*parked|namecheap.com.*parking" <<< "$lower"; then
    return 0
  fi

  # --- Specific provider / template indicators ---
  if grep -q "comp-is-parked" <<< "$body"; then
    return 0
  fi

  if grep -qi 'class="[^"]*is-parked' <<< "$body"; then
    return 0
  fi

  if grep -qi "youstarsbuilding\.com/sxp" <<< "$body"; then
    return 0
  fi

  if grep -qi "adsdeli - domain - landingpage" <<< "$lower"; then
    return 0
  fi

  # Fallback: not clearly parked
  return 1
}

# Log a single line to the results file, and optionally to filtered list
log_result() {
  local url="$1"
  local https_code="$2"
  local http_code="$3"
  local status="$4"

  printf "%s${delim}%s${delim}%s${delim}%s\n" \
    "$url" "$https_code" "$http_code" "$status" >> "$results_file"

  # If a STATUS_FILTER is set, also write matching URLs to the second file
  if [ -n "$STATUS_FILTER" ] && [ "$status" = "$STATUS_FILTER" ]; then
    echo "$url" >> "$filtered_targets_file"
  fi
}

process_one_host() {
  local host_raw="$1"

  host_raw="$(echo "$host_raw" | tr -d '[:space:]')"
  [ -z "$host_raw" ] && return
  [[ "$host_raw" =~ ^# ]] && return

  local host
  host="$(normalise "$host_raw")"
  [ -z "$host" ] && return

  CURRENT_INDEX=$((CURRENT_INDEX + 1))

  echo
  echo "==============================="
  echo " [${CURRENT_INDEX}/${TOTAL_TARGETS}] Checking: $host"
  echo "==============================="

  # Check HTTPS and HTTP separately (no -L; first-hop code only)
  local status_https status_http
  status_https=$(curl -sS -o /dev/null -w "%{http_code}" \
    --user-agent "$BROWSER_UA" \
    --max-time 10 --connect-timeout 5 "https://$host" 2>/dev/null || echo "000")

  status_http=$(curl -sS -o /dev/null -w "%{http_code}" \
    --user-agent "$BROWSER_UA" \
    --max-time 10 --connect-timeout 5 "http://$host" 2>/dev/null || echo "000")

  echo "[*] $host -> HTTPS: $status_https, HTTP: $status_http"

  # Decide if host is reachable:
  # - If ANY side gives 2xx/3xx, we treat as reachable
  local reachable="0"
  local status="000"

  if [[ "$status_https" =~ ^[23] ]]; then
    reachable="1"
    status="$status_https"
  elif [[ "$status_http" =~ ^[23] ]]; then
    reachable="1"
    status="$status_http"
  else
    # Neither HTTPS nor HTTP gave 2xx/3xx. Take the "best" code for logging:
    if [ "$status_https" != "000" ]; then
      status="$status_https"
    else
      status="$status_http"
    fi
  fi

  if [ "$reachable" = "0" ]; then
    echo "    => No 2xx/3xx on HTTPS or HTTP; marking as DEAD"
    log_result "$host" "$status_https" "$status_http" "DEAD"
    sleep "$DELAY"
    return
  fi

  echo "[*] $host -> FINAL HTTP $status (reachable)"

  # Reachable: now get body and run parked detection
  local snippet
  snippet="$(get_body_snippet "$host")"

  if [ -z "$snippet" ]; then
    if [[ "$status" =~ ^3 ]]; then
      echo "    => Redirect but no body from final target; marking as REDIRECT-NO-BODY"
      log_result "$host" "$status_https" "$status_http" "REDIRECT-NO-BODY"
    else
      echo "    => No body content retrieved; marking as ERROR-NO-BODY"
      log_result "$host" "$status_https" "$status_http" "ERROR-NO-BODY"
    fi
    sleep "$DELAY"
    return
  fi

  # Heuristic parked detection
  if is_parked_page "$snippet"; then
    echo "    => Looks like a parked / domain reseller page"
    log_result "$host" "$status_https" "$status_http" "PARKED"
  else
    echo "    => Looks like a real/active site"
    log_result "$host" "$status_https" "$status_http" "ALIVE"
  fi

  sleep "$DELAY"
}

# --- Main dispatcher: single URL vs file ---
if [ -n "$SINGLE_URL" ]; then
  process_one_host "$SINGLE_URL"
else
  while IFS= read -r line; do
    process_one_host "$line"
  done < "$TARGETS_FILE"
fi

echo
echo "****************************"
echo "** All targets processed! **"
echo "****************************"
echo "[*] Results: $results_file"
if [ -n "$STATUS_FILTER" ]; then
  echo "[*] Filtered ${STATUS_FILTER} URLs: $filtered_targets_file"
fi
