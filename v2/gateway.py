# Full server with keys.json admin endpoints, bans, rate limiting,
# cache, request limits, logging, dynamic URLs management, and admin endpoints.

import os
import time
import json
import signal
import logging
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs
import requests
from collections import defaultdict, deque
import threading
import re
import secrets
import hashlib

# ============================================================
# Configuration (env vars)
# ============================================================

SOURCE_URL = os.getenv("SOURCE_URL")
OLD_BASE = os.getenv("OLD_BASE")
OLD_CREDS = os.getenv("OLD_CREDS")

HTTP_PORT = int(os.getenv("HTTP_PORT", "8080"))

# NEW_URLS will be loaded from urls.json at startup; environment variables
# can provide initial defaults if urls.json does not exist.
NEW_URLS = []
for i in range(1, 26):
    val = os.getenv(f"NEW_URL{i}")
    if val:
        NEW_URLS.append(val)

SOURCE_REFRESH_INTERVAL_SECONDS = int(os.getenv("SOURCE_REFRESH_INTERVAL_SECONDS", "1800"))
CACHE_TTL_SECONDS = int(os.getenv("CACHE_TTL_SECONDS", "600"))
MAX_CACHE_USERS = int(os.getenv("MAX_CACHE_USERS", "100"))

RATE_LIMIT_REQUESTS = int(os.getenv("RATE_LIMIT_REQUESTS", "60"))
RATE_LIMIT_WINDOW_SECONDS = int(os.getenv("RATE_LIMIT_WINDOW_SECONDS", "60"))

REQUIRE_AUTH_KEYS = os.getenv("REQUIRE_AUTH_KEYS", "false").lower() == "true"
ADMIN_KEY = os.getenv("ADMIN_KEY", "")
ACCESS_KEYS = set(k.strip() for k in os.getenv("ACCESS_KEYS", "").split(",") if k.strip())

MAX_REQUEST_LINE = int(os.getenv("MAX_REQUEST_LINE", "1024"))

ENABLE_IP_BAN = os.getenv("ENABLE_IP_BAN", "true").lower() == "true"
ENABLE_KEY_BAN = os.getenv("ENABLE_KEY_BAN", "true").lower() == "true"
BAN_THRESHOLD = int(os.getenv("BAN_THRESHOLD", "10"))
BAN_DURATION_SECONDS = int(os.getenv("BAN_DURATION_SECONDS", "3600"))
BAD_EVENT_DECAY_SECONDS = int(os.getenv("BAD_EVENT_DECAY_SECONDS", "900"))

TLS_PROBE_SUPPRESS_SECONDS = 3600
tls_probe_last_seen = {}

OUTPUT_DIR = os.getenv("OUTPUT_DIR", "/output")
os.makedirs(OUTPUT_DIR, exist_ok=True)
LOG_FILE = os.path.join(OUTPUT_DIR, "gateway.log")
OLD_LOG_FILE = os.path.join(OUTPUT_DIR, "gateway.log.old")
BANS_FILE = os.path.join(OUTPUT_DIR, "bans.json")

KEYS_FILE = os.path.join(OUTPUT_DIR, "keys.json")
KEY_LENGTH = int(os.getenv("KEY_LENGTH", "32"))
KEYS_CLEANUP_INTERVAL = int(os.getenv("KEYS_CLEANUP_INTERVAL", "60"))

# Persistent URLs file
URLS_FILE = os.path.join(OUTPUT_DIR, "urls.json")

# ============================================================
# Logging setup
# ============================================================

logger = logging.getLogger("dynamic_m3u_gateway")
logger.setLevel(logging.INFO)

class JsonFormatter(logging.Formatter):
    def format(self, record):
        log_record = {
            "time": self.formatTime(record, self.datefmt),
            "level": record.levelname,
            "message": record.getMessage(),
        }
        return json.dumps(log_record)

formatter = JsonFormatter()

file_handler = logging.FileHandler(LOG_FILE, encoding="utf-8")
file_handler.setFormatter(formatter)

console = logging.StreamHandler()
console.setFormatter(formatter)

logger.addHandler(file_handler)
logger.addHandler(console)

# -------------------------
# State, keys, bans, helpers
# -------------------------

ban_state = {"ips": {}, "keys": {}}
ban_lock = threading.Lock()

def load_bans():
    if os.path.exists(BANS_FILE):
        try:
            with open(BANS_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
                ban_state["ips"] = data.get("ips", {})
                ban_state["keys"] = data.get("keys", {})
        except Exception:
            logger.exception("Failed to load bans file")

def save_bans_snapshot(snapshot):
    try:
        with open(BANS_FILE, "w", encoding="utf-8") as f:
            json.dump(snapshot, f, indent=2)
    except Exception:
        logger.exception("Failed to save bans file")

load_bans()

keys_lock = threading.Lock()
keys_data = {"clients": {}}

def save_keys_atomic(path: str, data: dict):
    tmp = path + ".tmp"
    os.makedirs(os.path.dirname(path), exist_ok=True)
    try:
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, sort_keys=True)
            f.flush()
            try:
                os.fsync(f.fileno())
            except Exception:
                pass
        os.replace(tmp, path)
        try:
            os.chmod(path, 0o600)
        except Exception:
            pass
    except Exception:
        logger.exception("Failed to save keys atomically")

def load_keys():
    global keys_data
    if not os.path.exists(KEYS_FILE):
        with keys_lock:
            keys_data = {"clients": {}}
            save_keys_atomic(KEYS_FILE, keys_data)
        return
    try:
        with open(KEYS_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        if not isinstance(data, dict):
            raise ValueError("keys.json malformed")
        with keys_lock:
            keys_data.clear()
            keys_data.update(data)
            if "clients" not in keys_data:
                keys_data["clients"] = {}
    except Exception:
        logger.exception("Failed to load keys.json, initializing empty keys")
        with keys_lock:
            keys_data.clear()
            keys_data.update({"clients": {}})
        save_keys_atomic(KEYS_FILE, keys_data)

def generate_candidate(length: int = KEY_LENGTH) -> str:
    return secrets.token_urlsafe(length * 2)[:length]

def key_prefix(key: str, chars: int = 8) -> str:
    h = hashlib.sha256(key.encode("utf-8")).hexdigest()
    return h[:chars]

def keys_cleanup_loop():
    while True:
        time.sleep(KEYS_CLEANUP_INTERVAL)
        now = int(time.time())
        removed = []

        with keys_lock:
            clients = keys_data.get("clients", {})
            for k, v in list(clients.items()):
                expires_at = v.get("expires_at")
                if expires_at and expires_at <= now:
                    removed.append(k)
                    del clients[k]
            if removed:
                keys_snapshot = json.loads(json.dumps(keys_data))
            else:
                keys_snapshot = None

        if keys_snapshot is not None:
            try:
                save_keys_atomic(KEYS_FILE, keys_snapshot)
            except Exception:
                logger.exception("Failed to persist keys after cleanup")

        for k in removed:
            logger.info(json.dumps({"event": "keys_cleanup_removed", "client_prefix": key_prefix(k)}))

# -------------------------
# URLs persistence and helpers
# -------------------------

def load_urls():
    global NEW_URLS
    if os.path.exists(URLS_FILE):
        try:
            with open(URLS_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
            if isinstance(data, list):
                NEW_URLS = data
            else:
                NEW_URLS = NEW_URLS or []
        except Exception:
            logger.exception("Failed to load urls.json, initializing from env")
            NEW_URLS = NEW_URLS or []
    else:
        # If no file exists, persist current NEW_URLS from env
        try:
            os.makedirs(os.path.dirname(URLS_FILE), exist_ok=True)
            with open(URLS_FILE, "w", encoding="utf-8") as f:
                json.dump(NEW_URLS, f, indent=2)
        except Exception:
            logger.exception("Failed to create urls.json from env")

def save_urls_snapshot(snapshot):
    try:
        tmp = URLS_FILE + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(snapshot, f, indent=2)
            f.flush()
            try:
                os.fsync(f.fileno())
            except Exception:
                pass
        os.replace(tmp, URLS_FILE)
    except Exception:
        logger.exception("Failed to save urls.json")

# -------------------------
# Caching, rate limiting, helpers
# -------------------------

source_cache = {"text": None, "last_fetch": 0.0, "last_hash": None}

user_cache = {}
user_cache_lock = threading.Lock()

rate_limit_data = defaultdict(deque)
rate_limit_lock = threading.Lock()

start_time = time.time()

http_server = None
shutdown_requested = False

def rotate_logs_on_shutdown():
    try:
        for h in list(logger.handlers):
            h.flush()
            h.close()
            logger.removeHandler(h)
        if os.path.exists(OLD_LOG_FILE):
            os.remove(OLD_LOG_FILE)
        if os.path.exists(LOG_FILE):
            os.rename(LOG_FILE, OLD_LOG_FILE)
    except Exception as e:
        print(f"Error rotating logs: {e}")

def sanitize_log_message(msg: str) -> str:
    msg = re.sub(r"[^\x20-\x7E]+", "", msg)
    return msg.strip()

def is_tls_probe(request_line: str) -> bool:
    return bool(re.search(r"[^\x20-\x7E]", request_line))

def record_tls_probe(ip: str):
    now = time.time()
    last = tls_probe_last_seen.get(ip, 0)
    if now - last >= TLS_PROBE_SUPPRESS_SECONDS:
        tls_probe_last_seen[ip] = now
        logger.info(json.dumps({"event": "tls_probe", "ip": ip}))

def decay_bad_events(entry):
    now = time.time()
    if now - entry.get("last_event", 0) > BAD_EVENT_DECAY_SECONDS:
        entry["bad_events"] = 0

def record_bad_event(ip=None, key=None, reason="unknown"):
    now = time.time()
    to_persist = False
    with ban_lock:
        if ip:
            entry = ban_state["ips"].setdefault(ip, {"bad_events": 0, "ban_until": 0, "last_event": now})
            decay_bad_events(entry)
            entry["bad_events"] += 1
            entry["last_event"] = now
            logger.info(json.dumps({
                "event": "bad_event",
                "type": "ip",
                "ip": ip,
                "reason": reason,
                "count": entry["bad_events"]
            }))
            if ENABLE_IP_BAN and entry["bad_events"] >= BAN_THRESHOLD:
                entry["ban_until"] = now + BAN_DURATION_SECONDS
                logger.info(json.dumps({
                    "event": "ip_banned",
                    "ip": ip,
                    "duration_seconds": BAN_DURATION_SECONDS
                }))
            to_persist = True

        if key:
            entry = ban_state["keys"].setdefault(key, {"bad_events": 0, "ban_until": 0, "last_event": now})
            decay_bad_events(entry)
            entry["bad_events"] += 1
            entry["last_event"] = now
            logger.info(json.dumps({
                "event": "bad_event",
                "type": "key",
                "key_prefix": key_prefix(key) if key else None,
                "reason": reason,
                "count": entry["bad_events"]
            }))
            if ENABLE_KEY_BAN and entry["bad_events"] >= BAN_THRESHOLD:
                entry["ban_until"] = now + BAN_DURATION_SECONDS
                logger.info(json.dumps({
                    "event": "key_banned",
                    "key_prefix": key_prefix(key),
                    "duration_seconds": BAN_DURATION_SECONDS
                }))
            to_persist = True

        if to_persist:
            ban_snapshot = json.loads(json.dumps(ban_state))
        else:
            ban_snapshot = None

    if ban_snapshot is not None:
        def _persist_bans(snapshot):
            try:
                save_bans_snapshot(snapshot)
            except Exception:
                logger.exception("Async save_bans_snapshot failed (record_bad_event)")
        threading.Thread(target=_persist_bans, args=(ban_snapshot,), daemon=True).start()

def is_ip_banned(ip):
    entry = ban_state["ips"].get(ip)
    if not entry:
        return False
    now = time.time()
    if entry["ban_until"] > now:
        return True
    if entry["ban_until"] != 0:
        entry["ban_until"] = 0
        entry["bad_events"] = 0
        save_bans_snapshot(json.loads(json.dumps(ban_state)))
        logger.info(json.dumps({"event": "ban_expired", "type": "ip", "value": ip}))
    return False

def is_key_banned(key):
    entry = ban_state["keys"].get(key)
    if not entry:
        return False
    now = time.time()
    if entry["ban_until"] > now:
        return True
    if entry["ban_until"] != 0:
        entry["ban_until"] = 0
        entry["bad_events"] = 0
        save_bans_snapshot(json.loads(json.dumps(ban_state)))
        logger.info(json.dumps({"event": "ban_expired", "type": "key", "value": key_prefix(key)}))
    return False

def fetch_source_playlist(force=False):
    now = time.time()
    if source_cache["text"] is not None and not force:
        if now - source_cache["last_fetch"] < SOURCE_REFRESH_INTERVAL_SECONDS:
            return source_cache["text"], False
    try:
        logger.info(json.dumps({"event": "fetch_source_start", "url": SOURCE_URL}))
        r = requests.get(SOURCE_URL, timeout=20)
        r.raise_for_status()
        text = r.text
        h = hash(text)
        changed = (h != source_cache["last_hash"])
        source_cache["text"] = text
        source_cache["last_fetch"] = now
        source_cache["last_hash"] = h
        logger.info(json.dumps({"event": "fetch_source_done", "changed": changed}))
        return text, changed
    except Exception as e:
        logger.error(json.dumps({"event": "fetch_source_error", "error": str(e)}))
        if source_cache["text"] is not None:
            return source_cache["text"], False
        raise

def rewrite_playlist(source_text, new_url, client_creds):
    return source_text.replace(OLD_BASE, new_url).replace(OLD_CREDS, client_creds)

def cleanup_user_cache():
    now = time.time()
    with user_cache_lock:
        keys_to_delete = [
            key for key, entry in user_cache.items()
            if now - entry["timestamp"] > CACHE_TTL_SECONDS
        ]
        for key in keys_to_delete:
            del user_cache[key]
        if len(user_cache) > MAX_CACHE_USERS:
            sorted_items = sorted(user_cache.items(), key=lambda kv: kv[1]["timestamp"])
            excess = len(user_cache) - MAX_CACHE_USERS
            for i in range(excess):
                del user_cache[sorted_items[i][0]]

def cache_cleanup_loop():
    while True:
        time.sleep(60)
        cleanup_user_cache()

def get_cached_playlist(user, password, url_index):
    key = (user, password, url_index)
    now = time.time()
    with user_cache_lock:
        entry = user_cache.get(key)
        if entry and now - entry["timestamp"] <= CACHE_TTL_SECONDS:
            entry["timestamp"] = now
            return entry["text"]
    return None

def set_cached_playlist(user, password, url_index, text):
    key = (user, password, url_index)
    now = time.time()
    with user_cache_lock:
        user_cache[key] = {"text": text, "timestamp": now}

def rate_limited(ip):
    now = time.time()
    with rate_limit_lock:
        q = rate_limit_data[ip]
        while q and now - q[0] > RATE_LIMIT_WINDOW_SECONDS:
            q.popleft()
        if len(q) >= RATE_LIMIT_REQUESTS:
            return True
        q.append(now)
        return False

def read_clean_logs(max_lines=200):
    logs = []
    try:
        with open(LOG_FILE, "r", encoding="utf-8") as f:
            lines = f.readlines()[-max_lines:]
        for line in lines:
            clean = sanitize_log_message(line)
            if not clean:
                continue
            try:
                logs.append(json.loads(clean))
            except:
                continue
    except Exception as e:
        logs.append({"error": f"Failed to read logs: {e}"})
    return logs

def get_stats():
    now = time.time()
    uptime = now - start_time
    with user_cache_lock:
        cache_entries = len(user_cache)
    source_age = now - source_cache["last_fetch"] if source_cache["text"] else None
    with rate_limit_lock:
        rate_ips = len(rate_limit_data)
    ban_info = {"ips": {}, "keys": {}}
    with ban_lock:
        for ip, entry in ban_state["ips"].items():
            decay_bad_events(entry)
            remaining = max(0, int(entry["ban_until"] - now)) if entry["ban_until"] > now else None
            ban_info["ips"][ip] = {
                "bad_events": entry["bad_events"],
                "banned": entry["ban_until"] > now,
                "ban_expires_in": remaining
            }
        for key, entry in ban_state["keys"].items():
            decay_bad_events(entry)
            remaining = max(0, int(entry["ban_until"] - now)) if entry["ban_until"] > now else None
            ban_info["keys"][key_prefix(key)] = {
                "bad_events": entry["bad_events"],
                "banned": entry["ban_until"] > now,
                "ban_expires_in": remaining
            }
    return {
        "health": "ok",
        "uptime_seconds": int(uptime),
        "auth_required": REQUIRE_AUTH_KEYS,
        "source_cached": source_cache["text"] is not None,
        "source_age_seconds": int(source_age) if source_age else None,
        "cache_entries": cache_entries,
        "max_cache_users": MAX_CACHE_USERS,
        "cache_ttl_seconds": CACHE_TTL_SECONDS,
        "source_refresh_interval_seconds": SOURCE_REFRESH_INTERVAL_SECONDS,
        "rate_limit_requests": RATE_LIMIT_REQUESTS,
        "rate_limit_window_seconds": RATE_LIMIT_WINDOW_SECONDS,
        "rate_limit_tracked_ips": rate_ips,
        "new_url_count": len(NEW_URLS),
        "enable_ip_ban": ENABLE_IP_BAN,
        "enable_key_ban": ENABLE_KEY_BAN,
        "ban_threshold": BAN_THRESHOLD,
        "ban_duration_seconds": BAN_DURATION_SECONDS,
        "bad_event_decay_seconds": BAD_EVENT_DECAY_SECONDS,
        "ban_state": ban_info
    }

# -------------------------
# HTTP Handler
# -------------------------

class GatewayHandler(BaseHTTPRequestHandler):

    def send_json(self, code: int, obj):
        try:
            body = json.dumps(obj, indent=2).encode("utf-8")
        except Exception:
            body = json.dumps({"error": "serialization_error"}).encode("utf-8")
        try:
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        except Exception:
            pass

    def extract_admin_key_from_headers(self):
        auth = self.headers.get("Authorization")
        if not auth:
            return None
        parts = auth.split(None, 1)
        if len(parts) == 2 and parts[0].lower() == "admin":
            return parts[1].strip()
        return None

    def is_valid_admin(self, admin_key=None):
        if admin_key is None:
            admin_key = self.extract_admin_key_from_headers()
        return bool(admin_key and admin_key == ADMIN_KEY)

    def is_valid_client_key(self, key):
        if not REQUIRE_AUTH_KEYS:
            return True
        if not key:
            return False
        if key in ACCESS_KEYS:
            return True
        with keys_lock:
            return key in keys_data.get("clients", {})

    def log_message(self, format, *args):
        msg = sanitize_log_message(format % args)
        logger.info(json.dumps({"event": "http_log", "message": msg}))

    def log_request(self, code='-', size='-'):
        try:
            code_int = int(code)
        except Exception:
            code_int = None
        if code_int == 400 and is_tls_probe(getattr(self, "requestline", "")):
            return
        self.log_message('"%s" %s %s', getattr(self, "requestline", ""), str(code), str(size))

    def handle_one_request(self):
        try:
            request_line = self.rfile.readline().decode("latin1")
        except Exception:
            return

        if not request_line:
            return

        self.requestline = request_line.rstrip("\r\n")
        self.raw_requestline = request_line.encode("latin1")
        self.request_version = "HTTP/1.1"
        self.command = None
        self.path = None

        try:
            self.connection.settimeout(10.0)
        except Exception:
            pass

        try:
            logger.info(json.dumps({
                "event": "handle_one_request_raw",
                "ip": self.client_address[0],
                "raw_requestline": sanitize_log_message(request_line)
            }))
        except Exception:
            pass

        if len(request_line) > MAX_REQUEST_LINE:
            ip = self.client_address[0]
            record_bad_event(ip=ip, reason="oversized_request_line")
            try:
                self.send_response(400)
                self.send_header("Content-Length", "0")
                self.end_headers()
            except Exception:
                pass
            return

        if is_tls_probe(self.requestline):
            ip = self.client_address[0]
            now = time.time()
            last = tls_probe_last_seen.get(ip, 0)
            if now - last >= 2:
                record_tls_probe(ip)
                record_bad_event(ip=ip, reason="tls_probe")
            tls_probe_last_seen[ip] = now
            try:
                self.send_response(400)
                self.send_header("Content-Length", "0")
                self.end_headers()
            except Exception:
                pass
            return

        if not self.parse_request():
            return

        if self.command == "GET":
            self.do_GET()
        elif self.command == "POST":
            self.do_POST()
        else:
            try:
                self.send_response(405)
                self.end_headers()
            except Exception:
                pass

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path
        query = parse_qs(parsed.query)

        ip = self.client_address[0]
        key = query.get("key", [None])[0]

        if ENABLE_IP_BAN and is_ip_banned(ip):
            logger.info(json.dumps({
                "event": "request_blocked",
                "reason": "ip_banned",
                "ip": ip,
                "path": path
            }))
            self.send_response(403)
            self.end_headers()
            return

        if ENABLE_KEY_BAN and key and is_key_banned(key):
            logger.info(json.dumps({
                "event": "request_blocked",
                "reason": "key_banned",
                "key_prefix": key_prefix(key),
                "ip": ip,
                "path": path
            }))
            self.send_response(403)
            self.end_headers()
            return

        if path == "/get":
            self.handle_get(query)
        elif path == "/clear_cache":
            if not self.is_valid_admin():
                record_bad_event(ip=ip, key=key, reason="invalid_admin_key")
                self.send_response(401)
                self.end_headers()
                return
            self.handle_clear_cache()
        elif path == "/urls":
            # Admin-only listing of dynamic URLs
            if not self.is_valid_admin():
                record_bad_event(ip=ip, key=key, reason="invalid_admin_key")
                self.send_response(401)
                self.end_headers()
                return
            self.handle_urls()
        elif path == "/log":
            if not self.is_valid_admin():
                record_bad_event(ip=ip, key=key, reason="invalid_admin_key")
                self.send_response(401)
                self.end_headers()
                return
            self.handle_log()
        elif path == "/health":
            if not self.is_valid_admin():
                record_bad_event(ip=ip, key=key, reason="invalid_admin_key")
                self.send_response(401)
                self.end_headers()
                return
            self.handle_health()
        elif path == "/clients":
            if not self.is_valid_admin():
                record_bad_event(ip=ip, key=key, reason="invalid_admin_key")
                self.send_response(401)
                self.end_headers()
                return
            self.handle_list_clients()
        elif path == "/bans":
            if not self.is_valid_admin():
                record_bad_event(ip=ip, key=key, reason="invalid_admin_key")
                self.send_response(401)
                self.end_headers()
                return
            self.handle_list_bans()
        else:
            record_bad_event(ip=ip, key=key, reason="invalid_endpoint")
            self.send_response(404)
            self.end_headers()

    def do_POST(self):
        try:
            logger.info(json.dumps({
                "event": "do_post_received",
                "ip": self.client_address[0],
                "path": self.path,
                "requestline": sanitize_log_message(getattr(self, "requestline", ""))
            }))
        except Exception:
            pass

        parsed = urlparse(self.path)
        path = parsed.path

        content_length = 0
        body_text = ""
        try:
            content_length = int(self.headers.get("Content-Length", 0))
        except Exception:
            content_length = 0

        if content_length:
            try:
                body_bytes = self.rfile.read(content_length)
                if not body_bytes:
                    raise TimeoutError("empty body read")
                body_text = body_bytes.decode("utf-8", errors="replace")
            except Exception as e:
                try:
                    logger.info(json.dumps({
                        "event": "post_body_read_error",
                        "ip": self.client_address[0],
                        "path": path,
                        "error": str(e)
                    }))
                except Exception:
                    pass
                try:
                    self.send_response(408)
                    self.send_header("Content-Type", "application/json")
                    self.end_headers()
                    self.wfile.write(json.dumps({"error": "request_timeout_or_invalid_body"}).encode("utf-8"))
                except Exception:
                    pass
                return
        else:
            body_text = ""

        try:
            body_json = json.loads(body_text) if body_text else {}
        except Exception:
            body_json = {}

        admin_key_header = self.extract_admin_key_from_headers()
        admin_key_body = body_json.get("admin_key")
        admin_key = admin_key_header or admin_key_body

        if path == "/add_key":
            if not admin_key or admin_key != ADMIN_KEY:
                record_bad_event(ip=self.client_address[0], key=None, reason="invalid_admin_key")
                self.send_response(401)
                self.end_headers()
                return
            self.handle_add_key_post(body_json, raw_body=body_text)
            return

        if path == "/remove_key":
            if not admin_key or admin_key != ADMIN_KEY:
                record_bad_event(ip=self.client_address[0], key=None, reason="invalid_admin_key")
                self.send_response(401)
                self.end_headers()
                return
            self.handle_remove_key_post(body_json)
            return

        if path == "/remove_ban":
            if not admin_key or admin_key != ADMIN_KEY:
                record_bad_event(ip=self.client_address[0], key=None, reason="invalid_admin_key")
                self.send_response(401)
                self.end_headers()
                return
            self.handle_remove_ban_post(body_json)
            return

        if path == "/add_url":
            if not admin_key or admin_key != ADMIN_KEY:
                record_bad_event(ip=self.client_address[0], key=None, reason="invalid_admin_key")
                self.send_response(401)
                self.end_headers()
                return
            self.handle_add_url_post(body_json)
            return

        if path == "/remove_url":
            if not admin_key or admin_key != ADMIN_KEY:
                record_bad_event(ip=self.client_address[0], key=None, reason="invalid_admin_key")
                self.send_response(401)
                self.end_headers()
                return
            self.handle_remove_url_post(body_json)
            return

        try:
            self.send_response(404)
            self.end_headers()
        except Exception:
            pass

    # -------------------------
    # GET handlers
    # -------------------------

    def handle_get(self, query):
        ip = self.client_address[0]
        key = query.get("key", [None])[0]

        if not self.is_valid_client_key(key):
            record_bad_event(ip=ip, key=key, reason="invalid_client_key")
            self.send_response(401)
            self.end_headers()
            return

        if rate_limited(ip):
            record_bad_event(ip=ip, key=key, reason="rate_limited")
            self.send_response(429)
            self.end_headers()
            return

        user = query.get("user", [None])[0]
        password = query.get("pass", [None])[0]
        url_param = query.get("url", [None])[0]

        if not user or not password or not url_param:
            record_bad_event(ip=ip, key=key, reason="missing_parameters")
            self.send_response(400)
            self.end_headers()
            return

        new_url = None
        url_index_key = None
        filename_suffix = None

        if url_param and (url_param.startswith("http://") or url_param.startswith("https://")):
            new_url = url_param
            url_index_key = new_url
            filename_suffix = "custom"
        else:
            try:
                idx = int(url_param[3:]) if url_param.upper().startswith("URL") else int(url_param)
            except Exception:
                record_bad_event(ip=ip, key=key, reason="invalid_url_param")
                self.send_response(400)
                self.end_headers()
                return

            if idx < 1 or idx > len(NEW_URLS):
                record_bad_event(ip=ip, key=key, reason="url_index_out_of_range")
                self.send_response(400)
                self.end_headers()
                return

            new_url = NEW_URLS[idx - 1]
            url_index_key = idx - 1
            filename_suffix = str(idx)

        client_creds = f"{user}/{password}"

        start = time.time()

        cached = get_cached_playlist(user, password, url_index_key)
        if cached:
            playlist = cached
            cache_hit = True
            source_refreshed = False
        else:
            source_text, source_refreshed = fetch_source_playlist()
            playlist = rewrite_playlist(source_text, new_url, client_creds)
            set_cached_playlist(user, password, url_index_key, playlist)
            cache_hit = False

        duration_ms = int((time.time() - start) * 1000)

        logger.info(json.dumps({
            "event": "playlist_served",
            "user": user,
            "pass": password,
            "key_prefix": key_prefix(key) if key else None,
            "ip": ip,
            "url_param": url_param,
            "cache_hit": cache_hit,
            "source_refreshed": source_refreshed,
            "duration_ms": duration_ms
        }))

        filename = f"{user}_{password}_url{filename_suffix}.m3u"

        self.send_response(200)
        self.send_header("Content-Type", "application/x-mpegURL")
        self.send_header("Content-Disposition", f'attachment; filename="{filename}"')
        self.end_headers()
        try:
            self.wfile.write(playlist.encode("utf-8"))
        except Exception:
            pass

    def handle_clear_cache(self):
        ip = self.client_address[0]
        with user_cache_lock:
            user_cache.clear()
        logger.info(json.dumps({
            "event": "cache_cleared",
            "admin_ip": ip
        }))
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        try:
            self.wfile.write(b"Cache cleared.\n")
        except Exception:
            pass

    def handle_urls(self):
        # Admin-only: list current NEW_URLS
        if not self.is_valid_admin():
            record_bad_event(ip=self.client_address[0], key=None, reason="invalid_admin_key")
            self.send_response(401)
            self.end_headers()
            return
        urls = [{"index": i+1, "url": u} for i, u in enumerate(NEW_URLS)]
        self.send_json(200, {"urls": urls})

    def handle_log(self):
        logs = read_clean_logs(200)
        self.send_json(200, {"logs": logs})

    def handle_health(self):
        stats = get_stats()
        self.send_json(200, stats)

    def handle_list_clients(self):
        now = int(time.time())
        with keys_lock:
            clients = keys_data.get("clients", {})
            client_list = []
            for k, v in clients.items():
                expires_at = v.get("expires_at")
                expires_in_hours = None
                if expires_at:
                    expires_in_hours = max(0, int((expires_at - now) / 3600))
                client_list.append({
                    "client_key_prefix": key_prefix(k),
                    "created_at": v.get("created_at"),
                    "expires_at": expires_at,
                    "expires_in_hours": expires_in_hours,
                    "last_used": v.get("last_used"),
                    "bad_events": v.get("bad_events"),
                    "meta": v.get("meta", {})
                })
        self.send_json(200, {"clients": client_list})

    def handle_list_bans(self):
        now = time.time()
        with ban_lock:
            ips = {}
            for ip, entry in ban_state.get("ips", {}).items():
                remaining = max(0, int(entry.get("ban_until", 0) - now)) if entry.get("ban_until", 0) > now else None
                ips[ip] = {"bad_events": entry.get("bad_events", 0), "banned": entry.get("ban_until", 0) > now, "ban_expires_in": remaining}
            keys = {}
            for k, entry in ban_state.get("keys", {}).items():
                remaining = max(0, int(entry.get("ban_until", 0) - now)) if entry.get("ban_until", 0) > now else None
                keys[key_prefix(k)] = {"bad_events": entry.get("bad_events", 0), "banned": entry.get("ban_until", 0) > now, "ban_expires_in": remaining}
        self.send_json(200, {"ips": ips, "keys": keys})

    # -------------------------
    # POST handlers (admin)
    # -------------------------

    def handle_add_key_post(self, body_json, raw_body=None):
        """
        Create one or more client keys. Avoid holding keys_lock while generating keys
        to prevent deadlocks. Persist asynchronously.
        """
        data = body_json or {}
        if not data and raw_body:
            try:
                data = json.loads(raw_body)
            except Exception:
                data = {}

        try:
            expires_hours = int(data.get("expires_hours", 24))
        except Exception:
            self.send_json(400, {"error": "invalid expires_hours"})
            return
        if expires_hours < 1:
            self.send_json(400, {"error": "expires_hours must be >= 1"})
            return

        meta = data.get("meta", {})
        try:
            count = int(data.get("count", 1))
        except Exception:
            self.send_json(400, {"error": "invalid count"})
            return
        if count < 1 or count > 1000:
            self.send_json(400, {"error": "count must be between 1 and 1000"})
            return

        created = []
        now = int(time.time())
        expires_at = now + int(expires_hours) * 3600

        # Generate-and-insert loop: generate candidate keys outside the lock,
        # then acquire the lock briefly to check/insert each one.
        for _ in range(count):
            while True:
                candidate = generate_candidate(KEY_LENGTH)
                # Insert under lock if still unique
                with keys_lock:
                    clients = keys_data.setdefault("clients", {})
                    if candidate not in clients and candidate not in created:
                        clients[candidate] = {
                            "created_at": now,
                            "expires_at": expires_at,
                            "last_used": None,
                            "bad_events": 0,
                            "meta": meta
                        }
                        created.append(candidate)
                        break
                # otherwise loop and try another candidate

        # Snapshot for persistence
        keys_snapshot = json.loads(json.dumps(keys_data))

        # Persist asynchronously so we don't block the request thread
        def _persist_keys(snapshot):
            try:
                save_keys_atomic(KEYS_FILE, snapshot)
            except Exception:
                logger.exception("Async save_keys_atomic failed")

        threading.Thread(target=_persist_keys, args=(keys_snapshot,), daemon=True).start()

        logger.info(json.dumps({
            "event": "add_key",
            "admin_prefix": key_prefix(self.extract_admin_key_from_headers() or ""),
            "created_count": len(created),
            "expires_hours": expires_hours
        }))

        # Return created keys immediately
        self.send_json(200, {"client_keys": created, "expires_at": expires_at})

    def handle_remove_key_post(self, body_json):
        client_key = body_json.get("client_key")
        if not client_key:
            self.send_response(400)
            self.end_headers()
            return

        removed = False
        with keys_lock:
            clients = keys_data.get("clients", {})
            if client_key in clients:
                del clients[client_key]
                removed = True
                keys_snapshot = json.loads(json.dumps(keys_data))
            else:
                keys_snapshot = None

        if removed:
            def _persist_keys(snapshot):
                try:
                    save_keys_atomic(KEYS_FILE, snapshot)
                except Exception:
                    logger.exception("Async save_keys_atomic failed (remove_key)")

            if keys_snapshot is not None:
                threading.Thread(target=_persist_keys, args=(keys_snapshot,), daemon=True).start()

            logger.info(json.dumps({
                "event": "remove_key",
                "admin_prefix": key_prefix(self.extract_admin_key_from_headers() or ""),
                "client_prefix": key_prefix(client_key)
            }))
            self.send_json(200, {"ok": True})
            return
        else:
            self.send_response(404)
            self.end_headers()
            return

    def handle_remove_ban_post(self, body_json):
        ip = body_json.get("ip")
        client_key = body_json.get("client_key")

        removed = False
        with ban_lock:
            if ip and ip in ban_state.get("ips", {}):
                del ban_state["ips"][ip]
                removed = True
            if client_key and client_key in ban_state.get("keys", {}):
                del ban_state["keys"][client_key]
                removed = True
            ban_snapshot = json.loads(json.dumps(ban_state))

        if removed:
            def _persist_bans(snapshot):
                try:
                    save_bans_snapshot(snapshot)
                except Exception:
                    logger.exception("Async save_bans_snapshot failed")

            threading.Thread(target=_persist_bans, args=(ban_snapshot,), daemon=True).start()

            logger.info(json.dumps({
                "event": "remove_ban",
                "admin_prefix": key_prefix(self.extract_admin_key_from_headers() or ""),
                "ip": ip,
                "client_key_prefix": key_prefix(client_key) if client_key else None
            }))
            self.send_json(200, {"ok": True})
        else:
            self.send_json(404, {"error": "not_found"})

    # -------------------------
    # URL management handlers
    # -------------------------

    def handle_add_url_post(self, body_json):
        # body_json: {"url": "https://...", "position": optional_int}
        url = (body_json or {}).get("url")
        pos = (body_json or {}).get("position")
        if not url or not isinstance(url, str):
            self.send_json(400, {"error": "missing_or_invalid_url"})
            return
        # Admin auth already checked by caller, but double-check
        if not self.is_valid_admin():
            record_bad_event(ip=self.client_address[0], key=None, reason="invalid_admin_key")
            self.send_response(401)
            self.end_headers()
            return

        try:
            url = url.strip()
            if pos is None:
                NEW_URLS.append(url)
            else:
                try:
                    idx = int(pos) - 1
                    if idx < 0:
                        idx = 0
                    if idx >= len(NEW_URLS):
                        NEW_URLS.append(url)
                    else:
                        NEW_URLS.insert(idx, url)
                except Exception:
                    NEW_URLS.append(url)
            snapshot = list(NEW_URLS)
            def _persist_urls(s):
                try:
                    save_urls_snapshot(s)
                except Exception:
                    logger.exception("Async save_urls_snapshot failed")
            threading.Thread(target=_persist_urls, args=(snapshot,), daemon=True).start()

            logger.info(json.dumps({"event": "add_url", "admin_prefix": key_prefix(self.extract_admin_key_from_headers() or ""), "url": url}))
            self.send_json(200, {"ok": True, "urls": [{"index": i+1, "url": u} for i, u in enumerate(NEW_URLS)]})
        except Exception:
            logger.exception("handle_add_url_post failed")
            self.send_json(500, {"error": "internal_error"})

    def handle_remove_url_post(self, body_json):
        # body_json: {"index": 2} or {"url": "https://..."}
        if not self.is_valid_admin():
            record_bad_event(ip=self.client_address[0], key=None, reason="invalid_admin_key")
            self.send_response(401)
            self.end_headers()
            return

        payload = body_json or {}
        removed = None
        try:
            if "index" in payload:
                try:
                    idx = int(payload.get("index")) - 1
                    if 0 <= idx < len(NEW_URLS):
                        removed = NEW_URLS.pop(idx)
                except Exception:
                    pass
            elif "url" in payload:
                url = payload.get("url")
                try:
                    NEW_URLS.remove(url)
                    removed = url
                except ValueError:
                    removed = None

            if removed is None:
                self.send_json(404, {"error": "not_found"})
                return

            snapshot = list(NEW_URLS)
            def _persist_urls(s):
                try:
                    save_urls_snapshot(s)
                except Exception:
                    logger.exception("Async save_urls_snapshot failed (remove)")
            threading.Thread(target=_persist_urls, args=(snapshot,), daemon=True).start()

            logger.info(json.dumps({"event": "remove_url", "admin_prefix": key_prefix(self.extract_admin_key_from_headers() or ""), "removed": removed}))
            self.send_json(200, {"ok": True, "removed": removed, "urls": [{"index": i+1, "url": u} for i, u in enumerate(NEW_URLS)]})
        except Exception:
            logger.exception("handle_remove_url_post failed")
            self.send_json(500, {"error": "internal_error"})

# -------------------------
# Signal handling and main
# -------------------------

def handle_signal(signum, frame):
    global shutdown_requested, http_server
    shutdown_requested = True
    if http_server:
        http_server.shutdown()

def main():
    global http_server

    logger.info(json.dumps({
        "event": "startup",
        "source_url": SOURCE_URL,
        "old_base": OLD_BASE,
        "old_creds": OLD_CREDS,
        "new_url_count_env": len(NEW_URLS),
        "cache_ttl_seconds": CACHE_TTL_SECONDS,
        "source_refresh_interval_seconds": SOURCE_REFRESH_INTERVAL_SECONDS,
        "max_cache_users": MAX_CACHE_USERS,
        "rate_limit_requests": RATE_LIMIT_REQUESTS,
        "rate_limit_window_seconds": RATE_LIMIT_WINDOW_SECONDS,
        "http_port": HTTP_PORT,
        "require_auth_keys": REQUIRE_AUTH_KEYS,
        "max_request_line": MAX_REQUEST_LINE,
        "enable_ip_ban": ENABLE_IP_BAN,
        "enable_key_ban": ENABLE_KEY_BAN,
        "ban_threshold": BAN_THRESHOLD,
        "ban_duration_seconds": BAN_DURATION_SECONDS,
        "bad_event_decay_seconds": BAD_EVENT_DECAY_SECONDS
    }))

    load_keys()
    load_bans()
    load_urls()

    t_cache = threading.Thread(target=cache_cleanup_loop, daemon=True)
    t_cache.start()

    t_keys = threading.Thread(target=keys_cleanup_loop, daemon=True)
    t_keys.start()

    signal.signal(signal.SIGTERM, handle_signal)
    signal.signal(signal.SIGINT, handle_signal)

    http_server = ThreadingHTTPServer(("", HTTP_PORT), GatewayHandler)

    try:
        http_server.serve_forever()
    finally:
        http_server.server_close()
        rotate_logs_on_shutdown()

if __name__ == "__main__":
    main()
