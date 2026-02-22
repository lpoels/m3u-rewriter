#!/usr/bin/env bash
# tests/run_all_functions_test.sh
# Comprehensive, careful end-to-end test script that exercises common admin and client flows.
# - Sends requests slowly to avoid triggering bans during normal checks.
# - Uses file-based JSON payloads to avoid quoting issues.
# - Adds curl timeouts and robust error handling to avoid hangs.
# - Optional ban test runs last and requires explicit confirmation.
#
# Usage:
#   GATEWAY="http://10.8.2.4:8080" ADMIN_KEY="REPLACEME" \
#     CONTAINER="m3u_rewriter_v2_test" OUTDIR="/output" ./tests/run_all_functions_test.sh
#
set -euo pipefail

# Configurable environment variables (override on command line)
GATEWAY="${GATEWAY:-http://10.8.2.4:8080}"
ADMIN_KEY="${ADMIN_KEY:-Adm1nT3stKey_ForLocalUseOnly_2026}"
CONTAINER="${CONTAINER:-m3u_rewriter_v2_test}"
OUTDIR="${OUTDIR:-/output}"
TMPDIR="${TMPDIR:-/tmp/m3u_test}"
SLEEP_SHORT="${SLEEP_SHORT:-1}"    # seconds between most client requests
SLEEP_LONG="${SLEEP_LONG:-2}"     # longer pause for admin operations
CURL_CONNECT_TIMEOUT="${CURL_CONNECT_TIMEOUT:-5}"
CURL_MAX_TIME="${CURL_MAX_TIME:-20}"
BAD_ITER_DEFAULT="${BAD_ITER:-8}"  # default iterations for optional ban test

mkdir -p "$TMPDIR"

# jq helper: pretty-print if available, otherwise cat
jq_cmd() {
  if command -v jq >/dev/null 2>&1; then
    jq "$@"
  else
    cat
  fi
}

# Cleanup temp files on exit
cleanup() {
  rm -rf "$TMPDIR" 2>/dev/null || true
}
trap cleanup EXIT

# Admin request helper: writes output to a temp file and returns "outfile status"
# Usage: read OUTFILE STATUS < <(admin_request METHOD PATH [DATA_FILE])
admin_request() {
  local method="$1"; shift
  local path="$1"; shift
  local datafile="${1:-}"
  local outf
  outf="$(mktemp "$TMPDIR/admin.XXXXXX.json")"
  local status
  if [ -n "$datafile" ] && [ -f "$datafile" ]; then
    status=$(curl -sS --fail --show-error \
      --connect-timeout "$CURL_CONNECT_TIMEOUT" --max-time "$CURL_MAX_TIME" \
      -X "$method" -H "Authorization: Admin ${ADMIN_KEY}" -H "Content-Type: application/json" \
      --data-binary @"$datafile" "${GATEWAY}${path}" -o "$outf" -w "%{http_code}" 2>&1) || status="000"
  else
    status=$(curl -sS --fail --show-error \
      --connect-timeout "$CURL_CONNECT_TIMEOUT" --max-time "$CURL_MAX_TIME" \
      -X "$method" -H "Authorization: Admin ${ADMIN_KEY}" \
      "${GATEWAY}${path}" -o "$outf" -w "%{http_code}" 2>&1) || status="000"
  fi

  # If curl printed the status code to stdout, it will be captured in $status.
  # Ensure status is a 3-digit code; otherwise set to 000.
  if [[ ! "$status" =~ ^[0-9]{3}$ ]]; then
    status="000"
  fi

  # Sleep to avoid rapid-fire admin ops
  sleep "$SLEEP_LONG"
  printf "%s %s\n" "$outf" "$status"
}

# Client request helper that returns HTTP status only (slow)
client_request_status() {
  local query="$1"
  local status
  status=$(curl -sS --connect-timeout "$CURL_CONNECT_TIMEOUT" --max-time "$CURL_MAX_TIME" -o /dev/null -w "%{http_code}" "${GATEWAY}${query}" || echo "000")
  sleep "$SLEEP_SHORT"
  printf "%s" "$status"
}

echo "=== run_all_functions_test.sh ==="
echo "GATEWAY=$GATEWAY CONTAINER=$CONTAINER OUTDIR=$OUTDIR"
echo

# 1) Health check
echo "--- Health ---"
read outf status < <(admin_request GET "/health")
echo "HTTP $status"
if [ -s "$outf" ]; then
  cat "$outf" | jq_cmd .
else
  echo "No body returned from /health (status $status)"
fi
echo

# 2) Create a temporary client key (expires short)
echo "--- Create key (ephemeral) ---"
payload="$(mktemp "$TMPDIR/payload.XXXXXX.json")"
cat > "$payload" <<'JSON'
{"expires_hours":1,"meta":{"note":"run_all_functions_test"}}
JSON

read outf status < <(admin_request POST "/add_key" "$payload")
echo "HTTP $status"
if [ "$status" -ne 200 ]; then
  echo "ERROR: /add_key returned HTTP $status. Response:"
  [ -s "$outf" ] && cat "$outf" || true
  exit 2
fi

KEY="$(jq -r '.client_keys[0] // empty' <"$outf" 2>/dev/null || true)"
if [ -z "$KEY" ]; then
  echo "ERROR: failed to parse client key from /add_key response"
  echo "Response:"
  cat "$outf"
  exit 2
fi
echo "Created KEY prefix: ${KEY:0:8}"
echo

# 3) Latch flow: use key with user alice (should latch)
echo "--- Latch test: first use with user=alice ---"
STATUS="$(client_request_status "/get?user=alice&pass=pass&url=1&key=${KEY}")"
echo "GET with key returned HTTP $STATUS (expect 200)"
if [ "$STATUS" -ne 200 ]; then
  echo "ERROR: latch request failed (status $STATUS)"
  # attempt to show server logs for diagnosis
  echo "Recent server logs (tail 50):"
  docker exec -i "${CONTAINER}" sh -c "tail -n 50 '${OUTDIR}/gateway.log' || true"
  exit 3
fi

# 4) Attempt to use same key with different user (bob) -> expect 403
echo "--- Key-user mismatch test (bob) ---"
STATUS="$(client_request_status "/get?user=bob&pass=pass&url=1&key=${KEY}")"
echo "GET with same key but user=bob returned HTTP $STATUS (expect 403)"
if [ "$STATUS" -ne 403 ]; then
  echo "WARNING: expected 403 for key-user mismatch, got $STATUS"
fi

# 5) Access using latched username without key (alice) -> expect 200
echo "--- Username-only access (alice) ---"
STATUS="$(client_request_status "/get?user=alice&pass=pass&url=1")"
echo "GET with user=alice (no key) returned HTTP $STATUS (expect 200)"
if [ "$STATUS" -ne 200 ]; then
  echo "ERROR: username-only access failed (status $STATUS)"
  exit 4
fi

# 6) List clients and confirm latched_user present
echo
echo "--- List clients (admin) ---"
read outf status < <(admin_request GET "/clients")
echo "HTTP $status"
if [ -s "$outf" ]; then
  cat "$outf" | jq_cmd '.clients[] | {client_key_prefix, latched_user, meta}'
else
  echo "No body returned from /clients (status $status)"
fi

# 7) Unlatch the key by prefix (use first 8 chars of key)
PREFIX="${KEY:0:8}"
echo
echo "--- Unlatch key by prefix ($PREFIX) ---"
read outf status < <(admin_request POST "/unlatch_key" <(cat <<JSON
{"client_key_prefix":"${PREFIX}"}
JSON
))
echo "HTTP $status"
[ -s "$outf" ] && cat "$outf" | jq_cmd . || echo "No body"
echo "Verify unlatch: /clients entry for prefix should show latched_user null"
read outf status < <(admin_request GET "/clients")
[ -s "$outf" ] && cat "$outf" | jq_cmd '.clients[] | select(.client_key_prefix == "'"${PREFIX}"'")' || echo "No clients body"

# 8) Add and remove a URL (slow)
echo
echo "--- Add URL ---"
read outf status < <(admin_request POST "/add_url" <(cat <<'JSON'
{"url":"https://run-all.test/stream","position":1}
JSON
))
echo "HTTP $status"
[ -s "$outf" ] && cat "$outf" | jq_cmd . || echo "No body"
echo "--- Remove URL (by url) ---"
read outf status < <(admin_request POST "/remove_url" <(cat <<'JSON'
{"url":"https://run-all.test/stream"}
JSON
))
echo "HTTP $status"
[ -s "$outf" ] && cat "$outf" | jq_cmd . || echo "No body"

# 9) Clear cache
echo
echo "--- Clear cache (admin) ---"
read outf status < <(admin_request GET "/clear_cache")
echo "HTTP $status"
[ -s "$outf" ] && cat "$outf" || echo "No body"

# 10) Show recent logs (admin)
echo
echo "--- Recent logs (admin) ---"
read outf status < <(admin_request GET "/log")
echo "HTTP $status"
[ -s "$outf" ] && cat "$outf" | jq_cmd . || echo "No logs returned"

# 11) Quick persistence check: ensure keys.json and urls.json exist and are valid JSON
echo
echo "--- Check keys.json and urls.json inside container ---"
if docker exec -i "${CONTAINER}" sh -c "test -f '${OUTDIR}/keys.json' && echo ok || echo missing" 2>/dev/null | grep -q ok; then
  echo "keys.json exists"
  docker exec -i "${CONTAINER}" sh -c "jq -e . '${OUTDIR}/keys.json' >/dev/null 2>&1 && echo 'keys.json valid JSON' || echo 'keys.json invalid or jq missing'"
else
  echo "keys.json missing in container at ${OUTDIR}/keys.json"
fi

if docker exec -i "${CONTAINER}" sh -c "test -f '${OUTDIR}/urls.json' && echo ok || echo missing" 2>/dev/null | grep -q ok; then
  echo "urls.json exists"
  docker exec -i "${CONTAINER}" sh -c "jq -e . '${OUTDIR}/urls.json' >/dev/null 2>&1 && echo 'urls.json valid JSON' || echo 'urls.json invalid or jq missing'"
else
  echo "urls.json missing in container at ${OUTDIR}/urls.json"
fi

# 12) Cleanup: remove the ephemeral key (admin)
echo
echo "--- Cleanup: remove ephemeral key ---"
read outf status < <(admin_request POST "/remove_key" <(cat <<JSON
{"client_key":"${KEY}"}
JSON
))
echo "HTTP $status"
[ -s "$outf" ] && cat "$outf" | jq_cmd . || echo "No body"

# 13) Optional ban test (runs last). Warn and require confirmation.
echo
echo "=== OPTIONAL: Ban test (last) ==="
echo "This test will intentionally send repeated bad requests to trigger ban logic."
echo "It may cause your IP to be temporarily banned. Run only if you want to test ban behavior."
read -r -p "Proceed with ban test? (y/N): " PROCEED_BAN
if [ "${PROCEED_BAN:-N}" != "y" ] && [ "${PROCEED_BAN:-N}" != "Y" ]; then
  echo "Skipping ban test. Script complete."
  exit 0
fi

echo "Proceeding with ban test. Sending slow repeated bad requests to avoid immediate rate-limit spikes."
BAD_ITER="${BAD_ITER_DEFAULT}"
for i in $(seq 1 "$BAD_ITER"); do
  echo "Ban test request $i/$BAD_ITER"
  curl -sS --connect-timeout "$CURL_CONNECT_TIMEOUT" --max-time "$CURL_MAX_TIME" -o /dev/null \
    "${GATEWAY}/get?user=baduser&pass=badpass&url=1" || true
  sleep 2
done

echo "Ban test completed. Check /bans (admin) to see results."
read outf status < <(admin_request GET "/bans")
echo "HTTP $status"
[ -s "$outf" ] && cat "$outf" | jq_cmd . || echo "No body"

echo
echo "=== run_all_functions_test.sh completed ==="
