#!/usr/bin/env bash
# tests/load_test.sh (Portainer-friendly)
# Load test using admin endpoints only. Start small and increase gradually.
set -euo pipefail

GATEWAY="${GATEWAY:-http://10.8.2.4:8080}"
ADMIN_KEY="${ADMIN_KEY:-Adm1nT3stKey_ForLocalUseOnly_2026}"
PAR="${PAR:-20}"
ITERS="${ITERS:-100}"
TMPDIR="${TMPDIR:-/tmp/m3u_test}"
CURL_CONNECT_TIMEOUT="${CURL_CONNECT_TIMEOUT:-5}"
CURL_MAX_TIME="${CURL_MAX_TIME:-15}"
SLEEP_SHORT="${SLEEP_SHORT:-0.05}"

mkdir -p "$TMPDIR"

echo "=== load_test.sh (admin-endpoint only) ==="
echo "GATEWAY=$GATEWAY PAR=$PAR ITERS=$ITERS"
echo

# Warmup
echo "--- Warmup: single add_key ---"
payload="$(mktemp "$TMPDIR/payload.XXXXXX.json")"
cat > "$payload" <<'JSON'
{"expires_hours":1,"meta":{"note":"warmup"}}
JSON
curl -sS --connect-timeout "$CURL_CONNECT_TIMEOUT" --max-time "$CURL_MAX_TIME" \
  -H "Authorization: Admin ${ADMIN_KEY}" -H "Content-Type: application/json" \
  --data-binary @"$payload" "${GATEWAY}/add_key" -o /dev/null || true
rm -f "$payload"
sleep 1

# Run parallel load: PAR concurrent workers, ITERS total requests
echo "--- Running load: ${ITERS} requests with concurrency ${PAR} ---"
seq "$ITERS" | xargs -n1 -P"$PAR" -I{} sh -c '
  payload="$(mktemp /tmp/m3u_test.payload.XXXXXX.json)"
  cat > "$payload" <<JSON
{"expires_hours":1,"meta":{"note":"load-test"}}
JSON
  curl -sS --connect-timeout 5 --max-time 15 -H "Authorization: Admin '"${ADMIN_KEY}"'" -H "Content-Type: application/json" --data-binary @"$payload" "'"${GATEWAY}"'/add_key" -o /dev/null || true
  rm -f "$payload"
  sleep '"$SLEEP_SHORT"'
'

echo "Load run completed."

# Check recent logs via /log
echo "--- Recent logs (admin /log) ---"
curl -sS -H "Authorization: Admin ${ADMIN_KEY}" "${GATEWAY}/log" | jq . || echo "log query failed"

echo
echo "load_test.sh completed."
