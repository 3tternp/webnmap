# Nmap Web Dashboard

A modern, web-based **nmap** scanning tool with a React frontend dashboard and a Python FastAPI backend. Launch scans from your browser, view live results, and explore open ports, services, versions, and OS fingerprints — just like WebMap, but self-hosted.

![Dashboard Preview](https://img.shields.io/badge/status-active-brightgreen)
![License](https://img.shields.io/badge/license-MIT-blue)

---

## Table of Contents

- [Architecture](#architecture)
- [Features](#features)
- [Quick Start](#quick-start)
  - [1. Backend (FastAPI + nmap)](#1-backend-fastapi--nmap)
  - [2. Frontend (React + TanStack Start)](#2-frontend-react--tanstack-start)
- [Scan Profiles](#scan-profiles)
- [API Endpoints](#api-endpoints)
- [Screenshots](#screenshots)
- [Security Notes](#security-notes)
- [License](#license)

---

## Architecture

```text
┌─────────────────┐         HTTP/JSON          ┌─────────────────────────┐
│   React UI      │  ◄─────────────────────►   │  Python FastAPI Backend │
│  (TanStack Start)│        CORS allowed         │      (nmap wrapper)     │
│   Runs anywhere  │                            │   Runs where nmap lives   │
└─────────────────┘                            └─────────────────────────┘
         │                                                 │
         │                                            ┌────┴────┐
         │                                            │  nmap   │
         │                                            │  binary │
         │                                            └────┬────┘
         │                                                 │
         │◄────────── XML output / parsed JSON ────────────┘
```

The **frontend** is a standalone React app built with [TanStack Start](https://tanstack.com/start), [Tailwind CSS](https://tailwindcss.com), and [shadcn/ui](https://ui.shadcn.com). It can be deployed to Vercel, Netlify, Lovable, or any static host.

The **backend** is a lightweight FastAPI service that wraps the system `nmap` binary. It must run on a machine (VPS, homelab, local workstation) where `nmap` is installed. Advanced scans (SYN stealth, UDP, OS detection) require root/sudo.

---

## Features

- **10 Built-in Scan Profiles** — Quick, Intense, Full TCP, UDP, SYN Stealth, OS Detection, Vulnerability scripts, Ping Sweep, Aggressive, and Custom
- **Live Polling** — Scan status updates in real-time while running
- **Results Table** — Host, Port, Protocol (TCP/UDP), State (open/closed/filtered), Service, Product/Version, CPE
- **Host Cards** — Individual host summaries with OS fingerprinting (when available)
- **Raw Output** — Full nmap XML/STDERR output for advanced users
- **Export JSON** — Download any scan result as a JSON file
- **Scan History** — All scans persisted in memory (backend) with cancel / delete controls
- **Backend Config** — Point the UI at any backend host via a settings dialog (stored in `localStorage`)
- **Optional Auth Token** — Secure the backend with an `X-Auth-Token` header

---

## Quick Start

### Prerequisites

| Component | Required Version |
|-----------|-----------------|
| Node.js   | 18+             |
| Bun       | 1.0+            |
| Python    | 3.10+           |
| nmap      | 7.80+           |

### 1. Backend (FastAPI + nmap)

Install dependencies:

```bash
# macOS
brew install nmap

# Debian / Ubuntu
sudo apt update && sudo apt install nmap

# Python packages
pip install fastapi uvicorn
```

Run the backend:

```bash
# Basic run (no sudo needed for TCP connect / version scans)
python nmap_backend.py

# With optional auth token
NMAP_AUTH_TOKEN=your-secret-token python nmap_backend.py

# On a custom port
NMAP_BACKEND_PORT=9000 python nmap_backend.py

# Root / sudo is required for SYN (-sS), UDP (-sU), and OS detection (-O)
sudo python nmap_backend.py
```

The backend starts on **`http://0.0.0.0:8765`** by default.

Verify it works:

```bash
curl http://localhost:8765/health
```

### 2. Frontend (React + TanStack Start)

Install dependencies:

```bash
bun install
```

Start the dev server:

```bash
bun dev
```

Open your browser at the printed URL (usually `http://localhost:3000`).

**Connect to backend:**

1. Click the **Backend** button in the top-right header.
2. Enter your backend URL (e.g., `http://localhost:8765` or `http://your-vps-ip:8765`).
3. Optionally enter an auth token if you configured `NMAP_AUTH_TOKEN`.
4. Click **Save**.

Now you're ready to scan!

---

## Scan Profiles

| Profile | nmap Arguments | Description | Needs Root |
|---------|---------------|-------------|------------|
| **Quick Scan** | `-T4 -F` | Top 100 ports, fast timing | No |
| **Intense Scan** | `-T4 -A -v` | OS, version, scripts, traceroute | No |
| **Full TCP Port Scan** | `-p- -T4 -sV` | All 65,535 TCP ports + version | No |
| **Service Version Scan** | `-sV -T4` | Detect service versions | No |
| **UDP Scan** | `-sU --top-ports 200 -T4` | Top 200 UDP ports | **Yes** |
| **SYN Stealth Scan** | `-sS -T4` | Half-open SYN scan | **Yes** |
| **OS Detection** | `-O -T4` | Fingerprint operating system | **Yes** |
| **Vulnerability Scripts** | `-sV --script vuln -T4` | Run NSE vuln category | No |
| **Ping Sweep** | `-sn` | Host discovery only | No |
| **Aggressive Full** | `-A -T4 -p- -sV --script default` | Everything (slow) | No |
| **Custom** | *user input* | Provide your own flags | *depends* |

---

## API Endpoints

Base URL: `http://<backend-host>:<port>`

| Method | Path | Description | Auth Required |
|--------|------|-------------|---------------|
| `POST` | `/scans` | Start a new scan | Optional |
| `GET` | `/scans` | List all scans | Optional |
| `GET` | `/scans/{id}` | Get a single scan | Optional |
| `POST` | `/scans/{id}/cancel` | Cancel a running scan | Optional |
| `DELETE` | `/scans/{id}` | Delete a scan | Optional |
| `GET` | `/health` | Health check + nmap availability | No |

All endpoints (except `/health`) accept an optional `X-Auth-Token` header.

### Example: Start a Scan

```bash
curl -X POST http://localhost:8765/scans \
  -H "Content-Type: application/json" \
  -H "X-Auth-Token: your-secret-token" \
  -d '{"target": "scanme.nmap.org", "args": "-T4 -F"}'
```

### Example: Get Results

```bash
curl http://localhost:8765/scans/<scan-id> \
  -H "X-Auth-Token: your-secret-token"
```

---

## Screenshots

The dashboard includes:

- **Header** with backend connection settings and refresh
- **New Scan Card** with target input, profile selector, optional port range, and start button
- **Scan History Sidebar** showing all past scans with status badges
- **Live Stats Cards** — Hosts up, Open ports, Filtered, Closed, Total ports
- **Results Tabs**:
  - *Ports & Services* — sortable table with all discovered ports
  - *Hosts* — per-host summaries with OS info
  - *Raw Output* — full nmap XML/STDERR for debugging

---

## Security Notes

- **Only scan hosts you own or have explicit written permission to test.** Unauthorized port scanning may violate laws in your jurisdiction and/or terms of service.
- The backend runs `nmap` with the arguments you provide — sanitize inputs and restrict access.
- Use `NMAP_AUTH_TOKEN` in production to prevent unauthorized scan submission.
- The backend CORS is set to `allow_origins=["*"]` by default. In production, lock this to your frontend domain.
- Scans are stored **in-memory only** — they disappear when the backend restarts. For persistence, wire in Redis or a database.

---

## Tech Stack

**Frontend**
- [React 19](https://react.dev)
- [TanStack Start](https://tanstack.com/start)
- [TanStack Query](https://tanstack.com/query)
- [Tailwind CSS 4](https://tailwindcss.com)
- [shadcn/ui](https://ui.shadcn.com)
- [Lucide Icons](https://lucide.dev)

**Backend**
- [Python 3.10+](https://python.org)
- [FastAPI](https://fastapi.tiangolo.com)
- [Uvicorn](https://www.uvicorn.org)
- [nmap](https://nmap.org)

---

## License

[MIT License](LICENSE) — © 2025 Nmap Web Dashboard Contributors.
