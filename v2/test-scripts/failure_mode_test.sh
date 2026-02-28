#!/usr/bin/env bash
# tests/failure_mode_test.sh (Portainer-friendly)
# Exercises malformed input and checks server behavior using admin endpoints only.
set -euo pipefail

GATEWAY="${GATEWAY:-http://10.8.2.4:8080}"
ADMIN_KEY="${ADMIN_KEY:-REPLACEME}"
TMPDIR="${TMPDIR:-/tmp/m3u_test}"
CURL_CONNECT_TIMEOUT="${CURL_CONNECT_TIMEOUT:-5}"
CURL_MAX_TIME="${CURL_MAX_TIME:-15}"
SLEEP_SHORT="${SLEEP_SHORT:-1}"

mkdir -p "$TMPDIR"

echo "=== failure_mode_test.sh (admin-endpoint only) ==="
echo "GATEWAY=$GATEWAY"
echo

# 1) Malformed JSON to /add_key
echo "--- Malformed JSON to /add_key ---"
curl -v --connect-timeout "$CURL_CONNECT_TIMEOUT" --max-time "$CURL_MAX_TIME" \
  -H "Authorization: Admin ${ADMIN_KEY}" -H "Content-Type: application/json" \
  -d "{bad json" "${GATEWAY}/add_key" || true
sleep "$SLEEP_SHORT"

# 2) Simulate slow client by sending a valid request but waiting between checks
echo "--- Slow client simulation (client-side pacing) ---"
payload="$(mktemp "$TMPDIR/payload.XXXXXX.json")"
cat > "$payload" <<'JSON'
{"expires_hours":1,"meta":{"note":"slow-client-test"}}
JSON
# Send request and wait a bit before checking response (server should handle it)
curl -sS --connect-timeout "$CURL_CONNECT_TIMEOUT" --max-time "$CURL_MAX_TIME" \
  -H "Authorization: Admin ${ADMIN_KEY}" -H "Content-Type: application/json" \
  --data-binary @"$payload" "${GATEWAY}/add_key" -o "$TMPDIR/slow_resp.json" || true
echo "Sleeping briefly to simulate slow client..."
sleep 3
echo "Response (if any):"
cat "$TMPDIR/slow_resp.json" || true
rm -f "$payload" "$TMPDIR/slow_resp.json"
sleep "$SLEEP_SHORT"

# 3) Simulate read-only output dir: cannot change permissions remotely via admin endpoints.
#    Prompt user to perform the chmod test in Portainer console if desired.
echo
echo "If you want to test read-only output dir behavior, open Portainer console and run:"
echo "  chmod -R a-w /output"
echo "Then press Enter to attempt an add_key (script will continue)."
read -r -p "Perform chmod in Portainer now? (y/N): " DO_CHMOD
if [ "${DO_CHMOD:-N}" = "y" ] || [ "${DO_CHMOD:-Y}" = "Y" ]; then
  echo "Waiting for you to perform chmod in Portainer, then press Enter..."
  read -r
  payload="$(mktemp "$TMPDIR/payload.XXXXXX.json")"
  cat > "$payload" <<'JSON'
{"expires_hours":1,"meta":{"note":"disk-test"}}
JSON
  curl -sS --connect-timeout "$CURL_CONNECT_TIMEOUT" --max-time "$CURL_MAX_TIME" \
    -H "Authorization: Admin ${ADMIN_KEY}" -H "Content-Type: application/json" \
    --data-binary @"$payload" "${GATEWAY}/add_key" -o "$TMPDIR/disk_resp.json" || true
  echo "Response (if any):"
  cat "$TMPDIR/disk_resp.json" || true
  rm -f "$payload" "$TMPDIR/disk_resp.json"
  echo "Remember to restore permissions in Portainer: chmod -R u+w /output"
fi

# 4) Check logs for persistence errors via /log
echo "--- Check /log for persistence errors ---"
curl -sS -H "Authorization: Admin ${ADMIN_KEY}" "${GATEWAY}/log" | jq '.[] | select(.event|test("save_keys|save_urls|save_bans") )' || echo "log query failed or no matching entries"

echo
echo "failure_mode_test.sh completed."
