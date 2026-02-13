\# M3U-Rewriter V2 — Dynamic Gateway



\## Overview



M3U-Rewriter V2 is a dynamic, on-demand IPTV playlist gateway that:



\- Fetches a source playlist from `SOURCE\_URL`

\- Rewrites stream URLs to NEW\_URL endpoints or client-supplied custom URLs

\- Replaces embedded credentials with client-provided credentials

\- Generates playlists on demand

\- Caches source and per-user playlists in memory

\- Applies rate limiting per IP

\- Exposes admin endpoints for cache control, URL listing, and log viewing

\- Writes detailed logs to `/output/gateway.log`



This version is stateless, scalable, and requires no pre-generated files.



---



\## Endpoints



\### `/get.php`



Main playlist endpoint.



Example:
	http://<server-ip>:8080/get.php?user=alice&pass=secret&url=1


Custom URL:
	http://<server-ip>:8080/get.php?user=alice&pass=secret&url=http://example.com:10



### `/clear_cache`

Clears:

- Source playlist cache
- Per-user playlist cache

### `/urls`

Lists available NEW_URL entries.

### `/log`

Returns the last 200 lines of the log.

---

## Environment Variables

### Required

- `SOURCE_URL`
- `OLD_BASE`
- `OLD_CREDS`

### URL Endpoints

- `NEW_URL1` … `NEW_URL25`

### Caching

- `CACHE_TTL_SECONDS`
- `SOURCE_CACHE_TTL_SECONDS`
- `MAX_CACHE_USERS`

### Rate Limiting

- `RATE_LIMIT_REQUESTS`
- `RATE_LIMIT_WINDOW_SECONDS`

### HTTP

- `HTTP_PORT`
- `TZ`

---

## Example Compose File


version: "3.9"

services:

m3u_rewriter_v2:
image: ghcr.io/lpoels/m3u-rewriter:latest
container_name: m3u_rewriter_v2
restart: unless-stopped

networks:
macvlan:
ipv4_address: 10.8.2.4

volumes:
- m3u_output_v2:/output

environment:
- SOURCE_URL=https://example.com/source.m3u
- OLD_BASE=http://old.server
- OLD_CREDS=olduser/oldpass

NEW_URL1=http://test1.rest

NEW_URL2=http://test2.rest

NEW_URL3=http://test3.rest

CACHE_TTL_SECONDS=600

SOURCE_CACHE_TTL_SECONDS=300

MAX_CACHE_USERS=100

RATE_LIMIT_REQUESTS=60

RATE_LIMIT_WINDOW_SECONDS=60

HTTP_PORT=8080

TZ=America/Toronto

volumes:
m3u_output_v2:





