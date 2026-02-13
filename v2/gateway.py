import os
import time
import logging
from logging.handlers import RotatingFileHandler
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs
import requests
from collections import defaultdict, deque
import threading

# ============================================================
# Configuration
# ============================================================

SOURCE_URL = os.getenv("SOURCE_URL")
OLD_BASE = os.getenv("OLD_BASE")
OLD_CREDS = os.getenv("OLD_CREDS")

HTTP_PORT = int(os.getenv("HTTP_PORT", "8080"))

MAX_URLS = 25

# Load NEW_URL1..NEW_URL25
NEW_URLS = []
for i in range(1, MAX_URLS + 1):
    val = os.getenv(f"NEW_URL{i}")
    if val:
        NEW_URLS.append(val)

if not SOURCE_URL or not OLD_BASE or not OLD_CREDS:
    raise RuntimeError("SOURCE_URL, OLD_BASE, and OLD_CREDS must be set.")

# Caching
CACHE_TTL_SECONDS = int(os.getenv("CACHE_TTL_SECONDS", "600"))
SOURCE_CACHE_TTL_SECONDS = int(os.getenv("SOURCE_CACHE_TTL_SECONDS", "300"))
MAX_CACHE_USERS = int(os.getenv("MAX_CACHE_USERS", "100"))

# Rate limiting
RATE_LIMIT_REQUESTS = int(os.getenv("RATE_LIMIT_REQUESTS", "60"))
RATE_LIMIT_WINDOW_SECONDS = int(os.getenv("RATE_LIMIT_WINDOW_SECONDS", "60"))

# Logging
OUTPUT_DIR = "/output"
os.makedirs(OUTPUT_DIR, exist_ok=True)
LOG_FILE = os.path.join(OUTPUT_DIR, "gateway.log")

logger = logging.getLogger("dynamic_m3u_gateway")
logger.setLevel(logging.INFO)

handler = RotatingFileHandler(LOG_FILE, maxBytes=5_000_000, backupCount=3)
formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
handler.setFormatter(formatter)

console = logging.StreamHandler()
console.setFormatter(formatter)

logger.addHandler(handler)
logger.addHandler(console)

# ============================================================
# Global State
# ============================================================

source_cache = {
    "text": None,
    "last_fetch": 0.0,
    "last_hash": None,
}

user_cache = {}  # key: (user, pass, url_index) -> {"text": str, "timestamp": float}
user_cache_lock = threading.Lock()

rate_limit_data = defaultdict(deque)
rate_limit_lock = threading.Lock()

start_time = time.time()

# ============================================================
# Helpers
# ============================================================

def fetch_source_playlist(force=False):
    now = time.time()
    if not force and source_cache["text"] is not None:
        if now - source_cache["last_fetch"] < SOURCE_CACHE_TTL_SECONDS:
            return source_cache["text"], False

    try:
        logger.info(f"Fetching source playlist from {SOURCE_URL}...")
        r = requests.get(SOURCE_URL, timeout=20)
        r.raise_for_status()
        text = r.text
        h = hash(text)
        if h != source_cache["last_hash"]:
            logger.info("Source playlist changed.")
        else:
            logger.info("Source playlist fetched (no change).")
        source_cache["text"] = text
        source_cache["last_fetch"] = now
        source_cache["last_hash"] = h
        return text, True
    except Exception as e:
        logger.error(f"Error fetching source playlist: {e}")
        if source_cache["text"] is not None:
            logger.info("Using cached source playlist due to error.")
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
    cleanup_user_cache()


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


def tail_log(lines=200):
    try:
        with open(LOG_FILE, "r", encoding="utf-8") as f:
            content = f.readlines()
        return "".join(content[-lines:])
    except Exception as e:
        return f"Error reading log: {e}\n"


# ============================================================
# HTTP Handler
# ============================================================

class GatewayHandler(BaseHTTPRequestHandler):

    def log_message(self, format, *args):
        logger.info("HTTP: " + format % args)

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path
        query = parse_qs(parsed.query)

        if path == "/get.php":
            self.handle_get_playlist(query)
        elif path == "/clear_cache":
            self.handle_clear_cache()
        elif path == "/urls":
            self.handle_urls()
        elif path == "/log":
            self.handle_log()
        else:
            self.send_response(404)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"Not Found\n")

    def handle_get_playlist(self, query):
        ip = self.client_address[0]

        if rate_limited(ip):
            logger.warning(f"Rate limit exceeded for IP {ip}")
            self.send_response(429)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"Too Many Requests\n")
            return

        user = query.get("user", [None])[0]
        password = query.get("pass", [None])[0]
        url_param = query.get("url", [None])[0]

        if not user or not password or not url_param:
            self.send_response(400)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"Missing required parameters: user, pass, url\n")
            return

        # Custom URL (not cached)
        if url_param.startswith("http://") or url_param.startswith("https://"):
            new_url = url_param
            custom = True
        else:
            custom = False
            try:
                if url_param.upper().startswith("URL"):
                    idx = int(url_param[3:])
                else:
                    idx = int(url_param)
            except ValueError:
                self.send_response(400)
                self.send_header("Content-Type", "text/plain")
                self.end_headers()
                self.wfile.write(b"Invalid url parameter.\n")
                return

            if idx < 1 or idx > len(NEW_URLS):
                self.send_response(400)
                self.send_header("Content-Type", "text/plain")
                self.end_headers()
                self.wfile.write(b"Requested URL index out of range.\n")
                return

            new_url = NEW_URLS[idx - 1]

        client_creds = f"{user}/{password}"

        start = time.time()

        # Cached only if NOT custom URL
        if not custom:
            cached = get_cached_playlist(user, password, idx - 1)
            if cached:
                logger.info(f"Cache HIT for user={user}, url={url_param}, ip={ip}")
                playlist = cached
                cache_hit = True
                source_refreshed = False
            else:
                logger.info(f"Cache MISS for user={user}, url={url_param}, ip={ip}")
                source_text, source_refreshed = fetch_source_playlist()
                playlist = rewrite_playlist(source_text, new_url, client_creds)
                set_cached_playlist(user, password, idx - 1, playlist)
                cache_hit = False
        else:
            logger.info(f"Custom URL request from user={user}, ip={ip}")
            source_text, source_refreshed = fetch_source_playlist()
            playlist = rewrite_playlist(source_text, new_url, client_creds)
            cache_hit = False

        duration_ms = int((time.time() - start) * 1000)

        logger.info(
            f"Served playlist: user={user}, ip={ip}, url={url_param}, "
            f"cache_hit={cache_hit}, source_refreshed={source_refreshed}, "
            f"duration={duration_ms}ms"
        )

        self.send_response(200)
        self.send_header("Content-Type", "application/x-mpegURL")
        self.end_headers()
        self.wfile.write(playlist.encode("utf-8"))

    def handle_clear_cache(self):
        ip = self.client_address[0]
        logger.info(f"/clear_cache called from IP {ip}")

        with user_cache_lock:
            user_cache.clear()
        source_cache["text"] = None
        source_cache["last_fetch"] = 0.0
        source_cache["last_hash"] = None

        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(b"Cache cleared.\n")

    def handle_urls(self):
        ip = self.client_address[0]
        logger.info(f"/urls requested from IP {ip}")

        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()

        lines = ["Available URLs:\n"]
        for i, url in enumerate(NEW_URLS, start=1):
            lines.append(f"URL{i} -> {url}\n")
        self.wfile.write("".join(lines).encode("utf-8"))

    def handle_log(self):
        ip = self.client_address[0]
        logger.info(f"/log requested from IP {ip}")

        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()

        content = tail_log(lines=200)
        self.wfile.write(content.encode("utf-8"))


# ============================================================
# Main
# ============================================================

def main():
    logger.info("============================================================")
    logger.info("Dynamic M3U Gateway V2 Startup")
    logger.info("============================================================")
    logger.info(f"SOURCE_URL: {SOURCE_URL}")
    logger.info(f"OLD_BASE: {OLD_BASE}")
    logger.info(f"OLD_CREDS: {OLD_CREDS}")
    logger.info(f"Detected NEW_URL entries: {len(NEW_URLS)}")
    for i, url in enumerate(NEW_URLS, start=1):
        logger.info(f"  NEW_URL{i}: {url}")
    logger.info(f"CACHE_TTL_SECONDS: {CACHE_TTL_SECONDS}")
    logger.info(f"SOURCE_CACHE_TTL_SECONDS: {SOURCE_CACHE_TTL_SECONDS}")
    logger.info(f"MAX_CACHE_USERS: {MAX_CACHE_USERS}")
    logger.info(f"RATE_LIMIT_REQUESTS: {RATE_LIMIT_REQUESTS}")
    logger.info(f"RATE_LIMIT_WINDOW_SECONDS: {RATE_LIMIT_WINDOW_SECONDS}")
    logger.info(f"HTTP_PORT: {HTTP_PORT}")
    logger.info("============================================================")

    server = ThreadingHTTPServer(("", HTTP_PORT), GatewayHandler)
    logger.info(f"HTTP server listening on port {HTTP_PORT}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        logger.info("Shutting down server...")
        server.server_close()


if __name__ == "__main__":
    main()
