# M3U‑Rewriter — M3U Playlist Rewriting Toolkit

M3U‑Rewriter is a toolkit for updating/editing an M3U playlist by rewriting stream URLs and credentials.  
It exists in two versions — **V1** and **V2** — each designed for different environments and performance needs.

All versions of M3U‑Rewriter were originally intended for LAN environments.  
V2.2 now includes optional authentication + ban protection for WAN/VPS use.

---

## 📌 Version Overview

### **V1 — File‑Based Playlist Rewriter**
A scheduled, file‑generation system that rewrites playlists at fixed intervals.

**Strengths**
- Extremely fast delivery to clients  
- Predictable, pre‑generated output  
- Up to 25 pairs of credentials/URL replacements  
- Edited M3U files served via HTTP  
- Ideal for small LAN environments  
- Great when clients request the same playlist repeatedly  

**Trade‑offs**
- Higher hardware/storage usage  
- Generates multiple files  
- Less flexible for dynamic or per‑request customization  

---

### **V2 — Dynamic Playlist Gateway (V2.2 Hardened Edition)**  
A real‑time gateway that rewrites playlists on demand.

**Strengths**
- Very low hardware requirements  
- Scales well with many clients  
- No file generation  
- Supports custom URLs per request  
- Provides admin endpoints (/log, /health, /urls)  
- Memory‑based caching  
- Optional authentication  
- Optional IP/key ban system  
- Optional WAN‑safe hardening  

**Trade‑offs**
- Slightly slower per request (rewriting happens live)  
- More moving parts  
- Requires a running service for every request  

---

## 🧭 Choosing Between V1 and V2

| Requirement / Environment | Choose V1 | Choose V2 |
|---------------------------|-----------|-----------|
| Small LAN with a few devices | ✅ | |
| Want instant playlist delivery | ✅ | |
| Prefer pre‑generated files | ✅ | |
| Low‑power hardware (Pi, VM, container) | | ✅ |
| Many clients or frequent requests | | ✅ |
| Need custom URLs per request | | ✅ |
| Want admin endpoints (/log, /health) | | ✅ |
| Need WAN‑safe protections | | ✅ |

Both versions are valid — the right choice depends on your environment.

---

## 📁 Repository Structure
/v1     → File‑based playlist rewriter (scheduled generation)
/v2     → Dynamic gateway (on‑demand rewriting)
/output → Runtime logs and generated files (Docker volume)

Each version includes its own README with installation instructions and examples.

---

## 📜 License

This project is open‑source and free to use.
