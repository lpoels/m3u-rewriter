#!/usr/bin/env bash
# tests/concurrency_test.sh (Portainer-friendly)
# Concurrent admin operations via HTTP only; paced to avoid bans.
set -euo pipefail

GATEWAY="${GATEWAY:-http://10.8.2.4:8080}"
ADMIN_KEY="${ADMIN_KEY:-REPLACEME}"
PAR="${PAR:-15}"
TMPDIR="${TMPDIR:-/tmp/m3u_test}"
CURL_CONNECT_TIMEOUT="${CURL_CONNECT_TIMEOUT:-5}"
CURL_MAX_TIME="${CURL_MAX_TIME:-15}"
SLEEP_SHORT="${SLEEP_SHORT:-0.2}"
SLEEP_LONG="${SLEEP_LONG:-1}"

mkdir -p "$TMPDIR"

echo "=== concurrency_test.sh (admin-endpoint only) ==="
echo "GATEWAY=$GATEWAY PAR=$PAR"
echo

# Background add_key helper (uses file payload)
add_key_bg() {
  local i="$1"
  local payload
  payload="$(mktemp "$TMPDIR/payload.XXXXXX.json")"
  cat > "$payload" <<JSON
{"expires_hours":1,"meta":{"note":"concurrent-${i}"}}
JSON
  curl -sS --connect-timeout "$CURL_CONNECT_TIMEOUT" --max-time "$CURL_MAX_TIME" \
    -H "Authorization: Admin ${ADMIN_KEY}" -H "Content-Type: application/json" \
    --data-binary @"$payload" "${GATEWAY}/add_key" >/dev/null 2>&1 || true
  rm -f "$payload"
}

# Run PAR concurrent add_key
echo "--- Concurrent add_key (${PAR}) ---"
for i in $(seq 1 "$PAR"); do
  add_key_bg "$i" &
  sleep "$SLEEP_SHORT"
done
wait
sleep "$SLEEP_LONG"
echo "add_key parallel requests completed."

# Check clients count
echo "--- Clients count ---"
curl -sS -H "Authorization: Admin ${ADMIN_KEY}" "${GATEWAY}/clients" | jq '.clients | length' || echo "clients query failed"
sleep "$SLEEP_LONG"

# Concurrent add_url
echo "--- Concurrent add_url (${PAR}) ---"
for i in $(seq 1 "$PAR"); do
  payload="$(mktemp "$TMPDIR/url.XXXXXX.json")"
  cat > "$payload" <<JSON
{"url":"https://concurrent.test/${i}"}
JSON
  curl -sS --connect-timeout "$CURL_CONNECT_TIMEOUT" --max-time "$CURL_MAX_TIME" \
    -H "Authorization: Admin ${ADMIN_KEY}" -H "Content-Type: application/json" \
    --data-binary @"$payload" "${GATEWAY}/add_url" >/dev/null 2>&1 || true &
  rm -f "$payload"
  sleep "$SLEEP_SHORT"
done
wait
sleep "$SLEEP_LONG"
echo "add_url parallel requests completed."

# Concurrent remove_url (best-effort)
echo "--- Concurrent remove_url (10 parallel) ---"
for i in $(seq 1 10); do
  curl -sS --connect-timeout "$CURL_CONNECT_TIMEOUT" --max-time "$CURL_MAX_TIME" \
    -H "Authorization: Admin ${ADMIN_KEY}" -H "Content-Type: application/json" \
    -d '{"index":1}' "${GATEWAY}/remove_url" >/dev/null 2>&1 || true &
  sleep "$SLEEP_SHORT"
done
wait
sleep "$SLEEP_LONG"

# Inspect final URLs and logs via admin endpoints
echo "--- Final URLs ---"
curl -sS -H "Authorization: Admin ${ADMIN_KEY}" "${GATEWAY}/urls" | jq . || echo "urls query failed"

echo "--- Recent logs (admin /log) ---"
curl -sS -H "Authorization: Admin ${ADMIN_KEY}" "${GATEWAY}/log" | jq . || echo "log query failed"

echo
echo "concurrency_test.sh completed."
