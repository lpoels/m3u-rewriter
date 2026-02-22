#!/usr/bin/env bash
# tests/persistence_test.sh (Portainer-friendly)
# Verifies keys and urls persist across graceful and abrupt restarts using admin endpoints only.
set -euo pipefail

GATEWAY="${GATEWAY:-http://10.8.2.4:8080}"
ADMIN_KEY="${ADMIN_KEY:-REPLACEME}"
TMPDIR="${TMPDIR:-/tmp/m3u_test}"
CURL_CONNECT_TIMEOUT="${CURL_CONNECT_TIMEOUT:-5}"
CURL_MAX_TIME="${CURL_MAX_TIME:-15}"
SLEEP_SHORT="${SLEEP_SHORT:-1}"
SLEEP_LONG="${SLEEP_LONG:-2}"

mkdir -p "$TMPDIR"

admin_request() {
  local method="$1"; shift
  local path="$1"; shift
  local datafile="${1:-}"
  local outf
  outf="$(mktemp "$TMPDIR/admin.XXXXXX.json")"
  if [ -n "$datafile" ] && [ -f "$datafile" ]; then
    status=$(curl -sS --fail --show-error --connect-timeout "$CURL_CONNECT_TIMEOUT" --max-time "$CURL_MAX_TIME" \
      -X "$method" -H "Authorization: Admin ${ADMIN_KEY}" -H "Content-Type: application/json" \
      --data-binary @"$datafile" "${GATEWAY}${path}" -o "$outf" -w "%{http_code}" 2>&1) || status="000"
  else
    status=$(curl -sS --fail --show-error --connect-timeout "$CURL_CONNECT_TIMEOUT" --max-time "$CURL_MAX_TIME" \
      -X "$method" -H "Authorization: Admin ${ADMIN_KEY}" "${GATEWAY}${path}" -o "$outf" -w "%{http_code}" 2>&1) || status="000"
  fi
  sleep "$SLEEP_LONG"
  printf "%s %s\n" "$outf" "$status"
}

client_status() {
  local q="$1"
  curl -sS --connect-timeout "$CURL_CONNECT_TIMEOUT" --max-time "$CURL_MAX_TIME" -o /dev/null -w "%{http_code}" "${GATEWAY}${q}" || echo "000"
  sleep "$SLEEP_SHORT"
}

echo "=== persistence_test.sh (admin-endpoint only) ==="
echo "GATEWAY=$GATEWAY"
echo

# Create ephemeral key
payload="$(mktemp "$TMPDIR/payload.XXXXXX.json")"
cat > "$payload" <<'JSON'
{"expires_hours":1,"meta":{"note":"persistence-test"}}
JSON

read outf status < <(admin_request POST "/add_key" "$payload")
echo "add_key HTTP $status"
if [ "$status" -ne 200 ]; then
  echo "ERROR: add_key failed"; [ -s "$outf" ] && cat "$outf"; exit 2
fi
KEY="$(jq -r '.client_keys[0] // empty' <"$outf" 2>/dev/null || true)"
if [ -z "$KEY" ]; then
  echo "ERROR: failed to parse key"; cat "$outf"; exit 2
fi
echo "Created KEY prefix: ${KEY:0:8}"
rm -f "$payload"

# Verify via /clients
echo "--- Verify key present via /clients ---"
read outf status < <(admin_request GET "/clients")
echo "clients HTTP $status"
[ -s "$outf" ] && jq '.clients[] | select(.client_key_prefix == "'"${KEY:0:8}"'")' <"$outf" || echo "clients body missing"

# Prompt for graceful restart in Portainer
echo
echo "Please perform a GRACEFUL restart of the container in Portainer now (Restart action)."
read -r -p "Press Enter after you initiated the restart in Portainer..."
# Poll /health until healthy
echo "Waiting for service to become healthy..."
until [ "$(curl -sS -H "Authorization: Admin ${ADMIN_KEY}" --connect-timeout 3 --max-time 5 "${GATEWAY}/health" >/dev/null 2>&1; echo $?)" -eq 0 ]; do
  sleep 2
done
echo "Service reachable. Re-checking /clients..."
read outf status < <(admin_request GET "/clients")
[ -s "$outf" ] && jq '.clients[] | select(.client_key_prefix == "'"${KEY:0:8}"'")' <"$outf" || echo "clients body missing"

# Prompt for abrupt stop/start (manual)
echo
echo "Now perform an ABRUPT stop (Stop) and then START the container in Portainer."
read -r -p "Press Enter after you have stopped and started the container..."
echo "Waiting for service to become healthy after abrupt restart..."
until [ "$(curl -sS -H "Authorization: Admin ${ADMIN_KEY}" --connect-timeout 3 --max-time 5 "${GATEWAY}/health" >/dev/null 2>&1; echo $?)" -eq 0 ]; do
  sleep 2
done
echo "Service reachable. Re-checking /clients..."
read outf status < <(admin_request GET "/clients")
[ -s "$outf" ] && jq '.clients[] | select(.client_key_prefix == "'"${KEY:0:8}"'")' <"$outf" || echo "clients body missing"

# Add a URL and verify via /urls
payload="$(mktemp "$TMPDIR/payload.XXXXXX.json")"
cat > "$payload" <<'JSON'
{"url":"https://persistence.test/stream"}
JSON
read outf status < <(admin_request POST "/add_url" "$payload")
echo "add_url HTTP $status"
[ -s "$outf" ] && cat "$outf"
rm -f "$payload"

echo "--- Verify /urls ---"
read outf status < <(admin_request GET "/urls")
echo "urls HTTP $status"
[ -s "$outf" ] && jq . <"$outf" || echo "No urls body"

echo
echo "persistence_test.sh completed."
