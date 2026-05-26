# Nmap Web Dashboard

A self-hosted, browser-based **nmap** scanning interface. Launch scans from your browser, view live results, and explore open ports, services, versions, and OS fingerprints.

```
┌─────────────────────┐         HTTP/JSON         ┌──────────────────────┐
│   React Frontend    │ ◄──────────────────────► │  Python FastAPI Backend│
│   (Vite + JSX)      │        CORS allowed        │    (nmap wrapper)     │
│   Runs anywhere     │                            │  Runs where nmap lives│
└─────────────────────┘                            └──────────────────────┘
```

---

## Quick Start

### 1. Backend (FastAPI + nmap)

```bash
# Install nmap
sudo apt update && sudo apt install nmap    # Debian/Ubuntu
brew install nmap                           # macOS

# Install Python dependencies
pip install fastapi uvicorn

# Run the backend
python nmap_backend.py

# With auth token (recommended in production)
NMAP_AUTH_TOKEN=your-secret python nmap_backend.py

# On custom port
NMAP_BACKEND_PORT=9000 python nmap_backend.py

# Root required for SYN/UDP/OS scans
sudo python nmap_backend.py
```

Backend starts on **`http://0.0.0.0:8765`** by default.

Verify: `curl http://localhost:8765/health`

### 2. Frontend (React + Vite)

```bash
bun install     # or: npm install
bun dev         # or: npm run dev
```

Then open the printed URL (usually `http://localhost:3000`).

Click **Backend** in the header → enter your backend URL → **Save**.

---

## Scan Profiles

| Profile | nmap Arguments | Description | Root? |
|---------|---------------|-------------|-------|
| Quick Scan | `-T4 -F` | Top 100 ports, fast | No |
| Intense Scan | `-T4 -A -v` | OS, version, scripts, traceroute | No |
| Full TCP | `-p- -T4 -sV` | All 65,535 TCP ports | No |
| Service Version | `-sV -T4` | Detect service versions | No |
| UDP Scan | `-sU --top-ports 200 -T4` | Top 200 UDP ports | **Yes** |
| SYN Stealth | `-sS -T4` | Half-open SYN scan | **Yes** |
| OS Detection | `-O -T4` | Fingerprint OS | **Yes** |
| Vuln Scripts | `-sV --script vuln -T4` | NSE vulnerability scripts | No |
| Ping Sweep | `-sn` | Host discovery only | No |
| Aggressive | `-A -T4 -p- -sV --script default` | Everything | No |
| Custom | *user input* | Your own flags | Depends |

---

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/scans` | Start a new scan |
| `GET` | `/scans` | List all scans |
| `GET` | `/scans/{id}` | Get scan details |
| `POST` | `/scans/{id}/cancel` | Cancel a running scan |
| `DELETE` | `/scans/{id}` | Delete a scan |
| `GET` | `/health` | Health check |

All endpoints (except `/health`) accept an optional `X-Auth-Token` header.

---

## Security Notes

- **Only scan hosts you own or have explicit written permission to scan.** Unauthorized scanning may violate laws.
- Set `NMAP_AUTH_TOKEN` to protect the backend from unauthorized access.
- The backend CORS is `allow_origins=["*"]` by default — lock to your frontend domain in production.
- Scans are stored **in-memory only** — they disappear when the backend restarts.

---

## Tech Stack

**Frontend** — React 19, TanStack Router, TanStack Start, Vite, Tailwind CSS 4, Lucide Icons

**Backend** — Python 3.10+, FastAPI, Uvicorn, nmap

---

## License

MIT License
