# M3U‑Rewriter V1 — File‑Based Playlist Rewriter

V1 is the original playlist rewriting system.  
It downloads a source playlist on a schedule, rewrites URLs and credentials, and saves the results as static files.

This version is ideal for small LAN environments where clients repeatedly request the same playlist and benefit from instant delivery.
Designed for use with EPGenius files shared via Google Drive; increase your security by keeping your REAL credientials off the internet!

---

## ✨ Features

- Scheduled source playlist downloads  
- URL rewriting using `NEW_URL1` … `NEW_URL25`  
- Credential rewriting using `NEW_CREDS1` … `NEW_CREDS25`  
- Automatic directory cleanup  
- Atomic file writes  
- Change detection (only rewrites when needed)  
- Lightweight HTTP server for serving generated playlists  

---

## 🧩 How It Works

1. The container downloads the source playlist at a fixed interval  
2. It rewrites URLs and credentials based on your environment variables  
3. It generates one playlist per profile  
4. Files are saved into `/output`  
5. Clients fetch the static files instantly  

This version does **not** generate playlists dynamically.

---

## ⚙️ Environment Variables

### Required
- `SOURCE_URL` — URL of the provider playlist  
- `OLD_BASE` — Base URL to replace  
- `OLD_CREDS` — Credentials to replace  

### URL Endpoints
- `NEW_URL1` … `NEW_URL25`

### Credential Profiles
- `ORDER_NUMBER1` … `ORDER_NUMBER25`  
- `NEW_CREDS1` … `NEW_CREDS25`

### Timing
- `UPDATE_INTERVAL_SECONDS`  
- `STARTUP_DELAY_SECONDS`

### HTTP
- `HTTP_PORT`

---

## 🐳 Example Docker Compose

```yaml
version: "3.9"

services:
  m3u_rewriter_v1:
    image: ghcr.io/lpoels/m3u-rewriter:v1
    container_name: m3u_rewriter_v1
    restart: unless-stopped

    networks:
      macvlan:
        ipv4_address: 10.8.2.3 #Static IP for container, must be within LAN subnet declared below

    volumes:
      - m3u_output_v1:/output

    environment:
      - SOURCE_URL=https://example.com/source.m3u #Link to EPGenius Google drive
      - OLD_BASE=http://old.server #URL contained within Source m3u file
      - OLD_CREDS=olduser/oldpass #User/Pass combination contained within source m3u file

      - NEW_URL1=http://new.server/stream1 #New URL's from provider, Up to 25
      - NEW_URL2=http://new.server/stream2

      - ORDER_NUMBER1=profile1 #Or Account Number; i use G2G order numbers to seperate crediential pairs
      - NEW_CREDS1=user1/pass1 #the user/pass combination for the above g2g subscription

      - ORDER_NUMBER2=profile2 # same as 1, Max of 25 profiles
      - NEW_CREDS2=user2/pass2 # same as 1, Max of 25 profiles

      - UPDATE_INTERVAL_SECONDS=1800
      - STARTUP_DELAY_SECONDS=30
      - HTTP_PORT=8080

volumes:
  m3u_output_v1:

networks:
  macvlan:
    driver: macvlan
    driver_opts:
      parent: eno1 #Your Physical Network Interface Name i.e. Eth0, Wlan0
    ipam:
      config:
        - subnet: 10.8.2.0/24 #Your Local Subnet
          gateway: 10.8.2.1 #Your Local Gateway IP
