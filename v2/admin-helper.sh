#!/usr/bin/env bash
# admin-helper.sh
# Interactive and non-interactive admin helper for the gateway
# Prompts for ADMIN_KEY at startup (never stored in script).
# Usage:
#   ./admin-helper.sh            # interactive menu (prompts for ADMIN_KEY each run)
#   ./admin-helper.sh health     # non-interactive single command
#   ./admin-helper.sh add_key '{"expires_hours":1,"meta":{"note":"test"}}'

set -euo pipefail

# Configuration
BASE_URL="${BASE_URL:-http://10.8.2.4:8080}"
CURL_OPTS="-sS --connect-timeout 5 --max-time 15"
JQ_BIN="$(command -v jq || true)"

# Always prompt for ADMIN_KEY at startup (do not read from script or env)
read -r -p "Enter ADMIN_KEY: " ADMIN_KEY

_auth_header() {
  printf "Authorization: Admin %s" "$ADMIN_KEY"
}

_do_curl() {
  # $1 = method, $2 = path, $3 = data (optional)
  local method="$1" path="$2" data="${3:-}"
  local headers=(-H "$(_auth_header)")
  if [ -n "$data" ]; then
    headers+=(-H "Content-Type: application/json")
    # echo the curl command to stderr for debugging
    echo curl $CURL_OPTS -X "$method" "${headers[@]}" -d "$data" "$BASE_URL$path" 1>&2
    curl $CURL_OPTS -X "$method" "${headers[@]}" -d "$data" "$BASE_URL$path"
  else
    echo curl $CURL_OPTS -X "$method" "${headers[@]}" "$BASE_URL$path" 1>&2
    curl $CURL_OPTS -X "$method" "${headers[@]}" "$BASE_URL$path"
  fi
}

pretty_print() {
  if [ -n "$JQ_BIN" ]; then
    jq .
  else
    cat
  fi
}

# Commands (ordered per requested menu)
cmd_health() {
  _do_curl GET "/health" | pretty_print
}

cmd_show_log() {
  _do_curl GET "/log" | pretty_print
}

cmd_list_clients() {
  _do_curl GET "/clients" | pretty_print
}

cmd_add_key() {
  local payload="${1:-}"
  if [ -z "$payload" ]; then
    read -r -p "Expires hours [1]: " expires
    expires="${expires:-1}"
    read -r -p "Note (optional): " note
    payload=$(printf '{"expires_hours":%s,"meta":{"note":"%s"}}' "$expires" "$(echo "$note" | sed 's/"/\\"/g')")
  fi
  _do_curl POST "/add_key" "$payload" | pretty_print
}

cmd_remove_key() {
  local key="${1:-}"
  if [ -z "$key" ]; then
    read -r -p "Client key to remove: " key
  fi
  payload=$(printf '{"client_key":"%s"}' "$key")
  _do_curl POST "/remove_key" "$payload" | pretty_print
}

cmd_unlatch_key() {
  local key="${1:-}" prefix="${2:-}" payload
  if [ -z "$key" ] && [ -z "$prefix" ]; then
    read -r -p "Client key to unlatch (leave blank to use prefix): " key
    if [ -z "$key" ]; then
      read -r -p "Client key prefix to unlatch: " prefix
    fi
  fi
  if [ -n "$key" ]; then
    payload=$(printf '{"client_key":"%s"}' "$key")
  else
    payload=$(printf '{"client_key_prefix":"%s"}' "$prefix")
  fi
  _do_curl POST "/unlatch_key" "$payload" | pretty_print
}

cmd_list_urls() {
  _do_curl GET "/urls" | pretty_print
}

cmd_add_url() {
  local url="${1:-}" pos="${2:-}" payload
  if [ -z "$url" ]; then
    read -r -p "URL to add: " url
  fi
  if [ -z "$pos" ]; then
    read -r -p "Position (optional, 1-based): " pos
  fi
  if [ -z "$pos" ]; then
    payload=$(printf '{"url":"%s"}' "$(echo "$url" | sed 's/"/\\"/g')")
  else
    payload=$(printf '{"url":"%s","position":%s}' "$(echo "$url" | sed 's/"/\\"/g')" "$pos")
  fi
  _do_curl POST "/add_url" "$payload" | pretty_print
}

cmd_remove_url() {
  local idx="${1:-}" url="${2:-}" payload
  if [ -z "$idx" ] && [ -z "$url" ]; then
    read -r -p "Index to remove (leave blank to remove by URL): " idx
    if [ -z "$idx" ]; then
      read -r -p "Exact URL to remove: " url
    fi
  fi
  if [ -n "$idx" ]; then
    payload=$(printf '{"index":%s}' "$idx")
  else
    payload=$(printf '{"url":"%s"}' "$(echo "$url" | sed 's/"/\\"/g')")
  fi
  _do_curl POST "/remove_url" "$payload" | pretty_print
}

cmd_list_bans() {
  _do_curl GET "/bans" | pretty_print
}

cmd_remove_ban() {
  local ip="${1:-}" ckey="${2:-}" payload
  if [ -z "$ip" ] && [ -z "$ckey" ]; then
    read -r -p "IP to remove (leave blank to remove by key): " ip
    if [ -z "$ip" ]; then
      read -r -p "Client key to remove: " ckey
    fi
  fi
  if [ -n "$ip" ]; then
    payload=$(printf '{"ip":"%s"}' "$ip")
  else
    payload=$(printf '{"client_key":"%s"}' "$ckey")
  fi
  _do_curl POST "/remove_ban" "$payload" | pretty_print
}

cmd_clear_cache() {
  _do_curl GET "/clear_cache" | pretty_print
}

print_menu() {
  clear
  cat <<'MENU'
================ Admin Helper =================
1  Health
2  Show Log
3  List Client Keys
4  Add Client Keys
5  Remove Client Keys
6  Unlatch Client Key
7  List URLs
8  Add URLs
9  Remove URLs
10 List Bans
11 Remove Ban
12 Clear Cache
0  Exit
===============================================
MENU
}

# Non-interactive single command mode
if [ $# -ge 1 ]; then
  cmd="$1"
  shift
  case "$cmd" in
    health) clear; cmd_health ;;
    log) clear; cmd_show_log ;;
    clients) clear; cmd_list_clients ;;
    add_key) clear; cmd_add_key "${1:-}" ;;
    remove_key) clear; cmd_remove_key "${1:-}" ;;
    unlatch_key) clear; cmd_unlatch_key "${1:-}" "${2:-}" ;;
    urls) clear; cmd_list_urls ;;
    add_url) clear; cmd_add_url "${1:-}" "${2:-}" ;;
    remove_url) clear; cmd_remove_url "${1:-}" "${2:-}" ;;
    bans) clear; cmd_list_bans ;;
    remove_ban) clear; cmd_remove_ban "${1:-}" "${2:-}" ;;
    clear_cache) clear; cmd_clear_cache ;;
    *) echo "Unknown command: $cmd"; exit 2 ;;
  esac
  exit 0
fi

# Interactive loop
while true; do
  print_menu
  read -r -p "Choose an option: " choice
  case "$choice" in
    1) clear; cmd_health ;;
    2) clear; cmd_show_log ;;
    3) clear; cmd_list_clients ;;
    4) clear; cmd_add_key ;;
    5) clear; cmd_remove_key ;;
    6) clear; cmd_unlatch_key ;;
    7) clear; cmd_list_urls ;;
    8) clear; cmd_add_url ;;
    9) clear; cmd_remove_url ;;
    10) clear; cmd_list_bans ;;
    11) clear; cmd_remove_ban ;;
    12) clear; cmd_clear_cache ;;
    0) clear; echo "Goodbye"; exit 0 ;;
    *) echo "Invalid choice"; sleep 1 ;;
  esac
  echo
  read -r -p "Press Enter to continue..." _dummy
done
