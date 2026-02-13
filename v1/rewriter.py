import time
import requests
import os
import logging
from logging.handlers import RotatingFileHandler
import threading
import http.server
import socketserver
import functools
import shutil

# ============================================================
# Configuration
# ============================================================

SOURCE_URL = os.getenv("SOURCE_URL")
OLD_BASE = os.getenv("OLD_BASE")
OLD_CREDS = os.getenv("OLD_CREDS")

OUTPUT_DIR = "/output"
TRIGGER_FILE = f"{OUTPUT_DIR}/force_update"

UPDATE_INTERVAL_SECONDS = int(os.getenv("UPDATE_INTERVAL_SECONDS", "1800"))
STARTUP_DELAY_SECONDS = int(os.getenv("STARTUP_DELAY_SECONDS", "30"))
HTTP_PORT = int(os.getenv("HTTP_PORT", "8080"))

MAX_URLS = 25
MAX_PROFILES = 25

# Load NEW_URL1…NEW_URL25
NEW_URLS = []
for i in range(1, MAX_URLS + 1):
    key = f"NEW_URL{i}"
    val = os.getenv(key)
    if val:
        NEW_URLS.append(val)

# Load ORDER_NUMBER1…ORDER_NUMBER25 and NEW_CREDS1…NEW_CREDS25
PROFILES = []
for i in range(1, MAX_PROFILES + 1):
    order = os.getenv(f"ORDER_NUMBER{i}")
    creds = os.getenv(f"NEW_CREDS{i}")
    if order and creds:
        PROFILES.append({"order": order, "creds": creds})

# ============================================================
# Logging Setup
# ============================================================

LOG_FILE = f"{OUTPUT_DIR}/rewriter.log"

logger = logging.getLogger("m3u_rewriter")
logger.setLevel(logging.INFO)

handler = RotatingFileHandler(LOG_FILE, maxBytes=5_000_000, backupCount=3)
formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
handler.setFormatter(formatter)

console = logging.StreamHandler()
console.setFormatter(formatter)

logger.addHandler(handler)
logger.addHandler(console)

# ============================================================
# Utility Functions
# ============================================================

def atomic_write(path: str, content: str):
    tmp_path = f"{path}.tmp"
    with open(tmp_path, "w", encoding="utf-8") as f:
        f.write(content)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp_path, path)


def rewrite_line(line: str, new_url: str, new_creds: str) -> str:
    if OLD_BASE:
        line = line.replace(OLD_BASE, new_url)
    if OLD_CREDS:
        line = line.replace(OLD_CREDS, new_creds)
    return line


def fetch_playlist():
    try:
        r = requests.get(SOURCE_URL, timeout=20)
        r.raise_for_status()
        return r.text
    except Exception as e:
        logger.error(f"Error fetching playlist: {e}")
        return None


def cleanup_directories(active_orders):
    for entry in os.listdir(OUTPUT_DIR):
        full_path = os.path.join(OUTPUT_DIR, entry)
        if os.path.isdir(full_path) and entry not in active_orders:
            logger.info(f"Removing stale directory: {entry}")
            shutil.rmtree(full_path, ignore_errors=True)


def generate_playlists(source_text):
    lines = source_text.splitlines()

    active_orders = [p["order"] for p in PROFILES]
    cleanup_directories(active_orders)

    for profile in PROFILES:
        order = profile["order"]
        creds = profile["creds"]

        profile_dir = os.path.join(OUTPUT_DIR, order)
        os.makedirs(profile_dir, exist_ok=True)

        for idx, new_url in enumerate(NEW_URLS, start=1):
            out_file = os.path.join(profile_dir, f"URL{idx}.m3u")
            rewritten = "\n".join(rewrite_line(line, new_url, creds) for line in lines)
            atomic_write(out_file, rewritten)
            logger.info(f"Wrote: {out_file}")


# ============================================================
# Main Update Logic
# ============================================================

def update_cycle(last_content):
    new_content = fetch_playlist()
    if new_content is None:
        return last_content, False

    if new_content == last_content:
        logger.info("No changes detected. Skipping rewrite.")
        return last_content, False

    logger.info("Source playlist changed. Regenerating all outputs...")
    generate_playlists(new_content)
    return new_content, True


def periodic_updater():
    logger.info("============================================================")
    logger.info("M3U REWRITER V2 STARTUP")
    logger.info("============================================================")
    logger.info(f"Startup delay: {STARTUP_DELAY_SECONDS} seconds")
    logger.info(f"Update interval: {UPDATE_INTERVAL_SECONDS} seconds")
    logger.info(f"Detected NEW_URL entries: {len(NEW_URLS)}")
    logger.info(f"Detected credential profiles: {len(PROFILES)}")
    logger.info("============================================================")

    time.sleep(STARTUP_DELAY_SECONDS)

    last_content = None

    while True:
        logger.info("------------------------------------------------------------")
        logger.info("Starting scheduled update...")

        last_content, changed = update_cycle(last_content)

        if changed:
            logger.info("Playlist updated successfully.")
        else:
            logger.info("No update required.")

        minutes = UPDATE_INTERVAL_SECONDS // 60
        logger.info(f"Next scan in {minutes} minutes.")

        for remaining in range(UPDATE_INTERVAL_SECONDS, 0, -1):
            if remaining == 60:
                logger.info("Scan starting in 1 minute...")
            time.sleep(1)


def start_http_server():
    try:
        handler = functools.partial(http.server.SimpleHTTPRequestHandler, directory=OUTPUT_DIR)
        with socketserver.TCPServer(("", HTTP_PORT), handler) as httpd:
            logger.info(f"HTTP server started on port {HTTP_PORT}")
            httpd.serve_forever()
    except Exception as e:
        logger.error(f"HTTP server failed: {e}")


# ============================================================
# Main
# ============================================================

if __name__ == "__main__":
    logger.info("Launching M3U Rewriter V2...")

    threading.Thread(target=periodic_updater, daemon=True).start()
    threading.Thread(target=start_http_server, daemon=True).start()

    while True:
        time.sleep(60)
