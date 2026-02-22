# M3U‑Rewriter V2 — Dynamic Playlist Gateway

V2 is a real‑time M3U editing gateway that rewrites playlists on demand.  
It is lightweight, scalable, and ideal for environments where many clients request playlists frequently.

Originally designed for use with EPGenius files shared via Google Drive;  
V2 now includes optional WAN‑safe security features so you can keep your REAL credentials off the internet.

---

## ✨ Key Features (V2.2)

- Fetches and caches the source playlist  
- Rewrites URLs and credentials dynamically  
- Per‑user playlist caching  
- Rate limiting per IP  
- Clean JSON logging  
- Admin endpoints for logs, stats, and cache control  
- Graceful shutdown with log rotation  
- No file generation required  
- **Optional authentication system (client keys + admin key)**
- **Optional Client/Key Latching system, ensures 1 key/1 user
- **IP and Key ban system with decay + auto‑expiration**  
- **Persistent bans stored in `/output/bans.json`**  
- **Request‑line length protection (anti‑flood / anti‑TLS‑probe)**  
- **Hardened `/health` endpoint with full ban telemetry**  
- **WAN/VPS‑safe when authentication + bans are enabled**

---

## 🧩 How It Works

1. A client requests:  
   `/get?key=ABC123&user=alice&pass=secret&url=http://example.com`  
2. The gateway loads the cached source playlist  
3. It rewrites:
   - Source URL  
   - Credentials  
   - URL index (Uses provided URL from request or Optional fixed URL's in Compose file)
   - If NEW_URL is declared in compose (NEW_URL1–NEW_URL25)= http://../get?..url=1-25
4. It returns a fresh playlist instantly  
5. The result is cached per user/profile  
6. Admin endpoints allow monitoring, logs, bans, cache control and key generation  
7. Optional ban system protects against abuse  

This version does **not** generate files, no user playlists are stored on the server.

---

## 🔐 Authentication (Optional)

Enable with:

- `REQUIRE_AUTH_KEYS=true`
- `KEY_LENGTH=32` - Length of generated client keys

### Client Access

Clients must include: `key=YOUR_ACCESS_KEY`

### Latching Client Keys
- When enabled, the first successful request that includes a new/valid client key and a username, binds (latches) that key to that username. 
- After latching:
  - That key can only be used with the latched username.
  - A request that supplies only the username (no key) is allowed if a non‑expired key is latched to that username.
  - Admins can unlatch a key to clear the binding (useful for typos or transfers).
  - Prevents a single client key from being shared across many end users (reseller abuse) while keeping onboarding simple: issue a key once, first use binds it.
- First Use:
```
curl "http://<HOST>:<PORT>/get?user=alice&pass=secret&url=1&key=<CLIENT_KEY>"
# first successful request binds <CLIENT_KEY> → "alice"
```
- Access After Latching:
```
# If <CLIENT_KEY> is latched to "alice", this will succeed without the key:
curl "http://<HOST>:<PORT>/get?user=alice&pass=secret&url=1"
```
- Unlatch a key (admin) 
```
curl -H "Authorization: Admin <ADMIN_KEY>" \
  -H "Content-Type: application/json" \
  -d '{"client_key_prefix":"abcd1234"}' \
  "http://<HOST>:<PORT>/unlatch_key"
```

## Admin access and key based auth

- This project uses an **Admin key** for administrative actions. Set the `ADMIN_KEY` environment variable in your deployment.
- Admin endpoints require formatted HTTP request:
- ` Use admin-helper script to interact with admin endpoints below`

### Admin helper script
Use the included `admin-helper` script to perform admin tasks (list clients, add/remove keys, list/remove bans, clear cache, view logs).

**Usage**
- Ensure to set "BASE_URL" vaiable at the top of admin-helper script, should point to the m3u-rewriter docker container
- Enter your `ADMIN_KEY` when the script launches.
- Run on Windows (PowerShell or cmd) or Git Bash.

**Admin Endpoints**
- `GET /health` — health and stats
- `GET /log` — Print the last 200 lines of Container Log
- `GET /clients` — list client keys
- `POST /add_key` — add client key(s)
- `POST /remove_key` — remove a client key
- `POST /unlatch_key` — clear a key’s `latched_user`
- `GET /urls` — list dynamic URLs (from urls.json).
- `POST /add_url` — add fixed URL.
- `POST /remove_url` — remove fixed URL
- `GET /bans` — list bans
- `POST /remove_ban` — remove a ban 
- `GET /clear_cache` — clear server cache


**Admin Endpoints - No Helper Tool**
- Admin endpoints can be used in various ways; if `REQUIRE_AUTH_KEYS = false` in the docker compose file,
  - Admins can simply visit http://host:PORT/health</SERVERIP>
- If `REQUIRE_AUTH_KEYS = true`, admins key must be declared in the docker compose file and will be used to access all endpoints
  - Admin keys are passed to the server via structured http requests with the admin key contained inside the headers, and data contained within the body of the request
  - i.e.
  ```
  curl -H "Authorization: Admin <ADMIN_KEY>" \
  -H "Content-Type: application/json" \
  -d '{"expires_hours":24,"meta":{"note":"issued to Alice"}}' \
  "http://<HOST>:<PORT>/add_key"
  ```

---

### Dynamic URLs management
- The server stores available target URLs in `/output/urls.json`. 
- Admins can list, add, and remove URLs at runtime using the admin-helper script

---

## 🚫 Ban System (Optional)

Enable with:

- `ENABLE_IP_BAN=true`  
- `ENABLE_KEY_BAN=true`

### What triggers a “bad event”?

- Invalid admin key  
- Invalid client key  
- Invalid URL index  
- Missing parameters  
- Rate limiting  
- Oversized request line  
- TLS probes  
- Invalid endpoints  

### Ban Logic

- If `bad_events >= BAN_THRESHOLD` → ban  
- Ban lasts `BAN_DURATION_SECONDS`  
- Bad events decay after `BAD_EVENT_DECAY_SECONDS`  
- Bans persist in `/output/bans.json`  
- `/health` shows:
  - bad event counts  
  - ban status  
  - time until unban  

---

## 🔗 Client Endpoints

### `/get`

With authentication:

- `http://<server>:8080/get?key=ABC123&user=alice&pass=secret` #Uses URL1 by Default
- OR
- `http://<server>:8080/get?key=ABC123&user=alice&pass=secret&url=1` #Declare Fixed URL
- OR
- `http://<server>:8080/get?key=ABC123&user=alice&pass=secret&url=http://example.com` #Set Custom URL

Without authentication:

- `http://<server>:8080/get?user=alice&pass=secret` #Uses URL1 by Default
- OR
- `http://<server>:8080/get?user=alice&pass=secret&url=1` #Declare Fixed URL
- OR
- `http://<server>:8080/get?user=alice&pass=secret&url=http://example.com` #Set Custom URL

---

## ⚙️ Environment Variables

### Required

- `SOURCE_URL`  
- `OLD_BASE`  
- `OLD_CREDS`  

### URL Endpoints

- `NEW_URL1` … `NEW_URL25` #Fixed Replacement URLs (optional)

### Caching

- `CACHE_TTL_SECONDS`  
- `SOURCE_REFRESH_INTERVAL_SECONDS`  
- `MAX_CACHE_USERS`

### Rate Limiting

- `RATE_LIMIT_REQUESTS`  
- `RATE_LIMIT_WINDOW_SECONDS`

### Authentication

- `REQUIRE_AUTH_KEYS=true|false`  
- `LATCH_CLIENT_KEYS=true` # enable latching (false = legacy behavior)
- `ADMIN_KEY=xxxx`
- `KEY_LENGTH=8`
- `KEYS_CLEANUP_INTERVAL=60`

### Ban System

- `ENABLE_IP_BAN=true|false`  
- `ENABLE_KEY_BAN=true|false`  
- `BAN_THRESHOLD=10`  
- `BAN_DURATION_SECONDS=3600`  
- `BAD_EVENT_DECAY_SECONDS=900`

### HTTP

- `HTTP_PORT`  
- `TZ`

---

## 🐳 Example Docker Compose

```yaml
version: "3.9"

services:
  m3u_rewriter_v2:
    image: ghcr.io/lpoels/m3u-rewriter:latest
    container_name: m3u_rewriter_v2
    restart: unless-stopped
    
    ports:
      - "8080:8080"

    networks:
      macvlan:
        ipv4_address: 10.8.2.4 #Static IP for container, must be within LAN subnet declared below

    volumes:
      - m3u_output_v2:/output

    environment:
      - SOURCE_URL=https://example.com/source.m3u #Link to EPGenius Google drive
      - OLD_BASE=http://old.server #URL contained within Source m3u file
      - OLD_CREDS=olduser/oldpass #User/Pass combination contained within source m3u file

      - NEW_URL1=http://new.server/stream1 #New URL's from provider, Up to 25
      - NEW_URL2=http://new.server/stream2

      - CACHE_TTL_SECONDS=600
      - SOURCE_REFRESH_INTERVAL_SECONDS=1800
      - MAX_CACHE_USERS=100

      - RATE_LIMIT_REQUESTS=60 #Amount of requests before ban
      - RATE_LIMIT_WINDOW_SECONDS=60 #duration of time requests are counted i.e. 60 requests in 60 seconds = 1 request per second

      # Authentication (optional)
      - REQUIRE_AUTH_KEYS=true #Enforce the use of Admin_keys on all endpoints, and client keys on file generation 
      - LATCH_CLIENT_KEYS=true # Latch the client_key, to the clients provided username; Client keys can only be used with 1 account
      - ADMIN_KEY=ADMIN123456789 #Set a STRONG admin key!
      - KEY_LENGTH=32 #Length of generated client keys
      - KEYS_CLEANUP_INTERVAL=60 #Check every __seconds for expired keys

      # Ban System (optional)
      - ENABLE_IP_BAN=true #Temp Ban IP Addresses for Abuse
      - ENABLE_KEY_BAN=true #Temp Ban Client Keys for Abuse
      - BAN_THRESHOLD=10 #Bad events accumulated before being banned
      - BAN_DURATION_SECONDS=3600 #Ban for 1 hour
      - BAD_EVENT_DECAY_SECONDS=900 #Bad events removed after xx seconds

      - HTTP_PORT=8080
      - TZ=America/Toronto #Your TimeZone for accurate Logs

volumes:
  m3u_output_v2:
    
networks:
  macvlan:
    driver: macvlan
    driver_opts:
      parent: eno1 #Your Physical Network Interface Name i.e. Eth0, Wlan0
    ipam:
      config:
        - subnet: 10.8.2.0/24 #Your Local Subnet
          gateway: 10.8.2.1 #Your Local Gateway IP

```

---  

## ⚙️ Security Notes

For LAN use, authentication can be disabled.

For WAN/VPS use:
- Enable authentication  
- Enable IP + key bans  
- Use a reverse proxy with HTTPS  
- Use strong admin keys  

---

## 🌐 Reverse‑Proxy + HTTPS Setup (Caddy or Nginx)

If you plan to expose V2 to the internet (VPS, remote access, Cloudflare Tunnel, etc.),  
you **must** run it behind a secure HTTPS reverse‑proxy.

Below are two recommended configurations:

- **Caddy (automatic HTTPS, easiest, recommended)**  
- **Nginx (manual HTTPS, more advanced)**  

Both examples assume your V2 gateway is running at:

`http://10.8.2.4:8080`

Replace `yourdomain.com` with your real domain.

---

## 🚀 Option 1 — Caddy Reverse‑Proxy (Recommended)

Caddy automatically handles:

- HTTPS certificates  
- Renewals  
- Redirects  
- HTTP/2  
- Security headers  

### 📁 Example Caddyfile

Create:

  `/etc/caddy/Caddyfile`

  ```caddy
  yourdomain.com {
      reverse_proxy 10.8.2.4:8080

      # Optional: Add security headers
      header {
          Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"
          X-Content-Type-Options "nosniff"
          X-Frame-Options "DENY"
          X-XSS-Protection "1; mode=block"
      }

      # Optional: Rate limit at proxy level
      rate_limit {
          zone default {
              key {remote_ip}
              events 20
              window 10s
          }
      }
  }
  ```

### Caddy via Docker

```yaml
version: "3.9"

services:
  caddy:
    image: caddy:latest
    container_name: caddy
    restart: unless-stopped
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./Caddyfile:/etc/caddy/Caddyfile
      - caddy_data:/data
      - caddy_config:/config

volumes:
  caddy_data:
  caddy_config:
```

Caddy will automatically issue and renew HTTPS certificates.

---

## 🔐 Option 2 — Nginx Reverse‑Proxy (Manual HTTPS)

Nginx is more traditional but requires manual certificate setup.

### Example Nginx Config

Create the file:
`/etc/nginx/sites-available/m3u-rewriter`

Paste the following into that file:

```nginx
server {
    listen 80;
    server_name yourdomain.com;

    # Redirect all HTTP to HTTPS
    return 301 https://$host$request_uri;
}

server {
    listen 443 ssl http2;
    server_name yourdomain.com;

    # SSL certificates (replace with your paths)
    ssl_certificate /etc/letsencrypt/live/yourdomain.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/yourdomain.com/privkey.pem;

    # Security headers
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload";
    add_header X-Content-Type-Options "nosniff";
    add_header X-Frame-Options "DENY";
    add_header X-XSS-Protection "1; mode=block";

    location / {
        proxy_pass http://10.8.2.4:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }
}
```

  Enable the site:
  ```
  -  sudo ln -s /etc/nginx/sites-available/m3u-rewriter /etc/nginx/sites-enabled/
  -  sudo nginx -t
  -  sudo systemctl restart nginx
  ```

  Get HTTPS Certificates (Certbot):
  ```
  -  sudo apt update
  -  sudo apt install certbot python3-certbot-nginx
  -  sudo certbot --nginx -d yourdomain.com
  ```
  
  Nginx will now serve your gateway securely. Replace yourdomain.com with your actual domain and adjust certificate paths if needed.
