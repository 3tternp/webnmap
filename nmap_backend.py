#!/usr/bin/env python3
"""
Nmap Web Dashboard — FastAPI Backend
Wraps the system nmap binary and exposes HTTP endpoints for scan management.

Usage:
    pip install fastapi uvicorn
    python nmap_backend.py

    # With auth token
    NMAP_AUTH_TOKEN=secret python nmap_backend.py

    # Root/sudo required for: SYN (-sS), UDP (-sU), OS detection (-O)
    sudo python nmap_backend.py
"""

import asyncio
import os
import re
import subprocess
import uuid
import xml.etree.ElementTree as ET
from datetime import datetime, timezone

from fastapi import FastAPI, HTTPException, Header
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

# ─── Config ──────────────────────────────────────────────────────────────────

AUTH_TOKEN = os.environ.get("NMAP_AUTH_TOKEN", "")
PORT       = int(os.environ.get("NMAP_BACKEND_PORT", "8765"))

SCANS: dict[str, dict] = {}

app = FastAPI(title="Nmap Web Dashboard API", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ─── Models ──────────────────────────────────────────────────────────────────

class StartScanRequest(BaseModel):
    target: str
    args: str = ""


class PortEntry(BaseModel):
    port: int
    protocol: str
    state: str
    service: str
    product: str | None = None
    version: str | None = None
    extrainfo: str | None = None
    cpe: str | None = None


class HostEntry(BaseModel):
    address: str
    hostname: str | None = None
    status: str
    os: str | None = None
    ports: list[PortEntry]


class ScanResponse(BaseModel):
    id: str
    target: str
    args: str
    status: str
    started_at: str
    finished_at: str | None = None
    command: str | None = None
    error: str | None = None
    hosts: list[HostEntry]
    raw: str | None = None


# ─── Helpers ─────────────────────────────────────────────────────────────────

def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


def require_auth(x_auth_token: str | None) -> None:
    if AUTH_TOKEN and x_auth_token != AUTH_TOKEN:
        raise HTTPException(status_code=401, detail="Invalid or missing X-Auth-Token header")


def parse_nmap_xml(xml_text: str) -> list[HostEntry]:
    hosts: list[HostEntry] = []
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return hosts

    for host_elem in root.findall("host"):
        addr_elem = host_elem.find("address")
        address = addr_elem.get("addr", "") if addr_elem is not None else ""

        hostname = None
        hostnames_elem = host_elem.find("hostnames")
        if hostnames_elem is not None:
            hname = hostnames_elem.find("hostname")
            if hname is not None:
                hostname = hname.get("name")

        status_elem = host_elem.find("status")
        status = status_elem.get("state", "unknown") if status_elem is not None else "unknown"

        os_name = None
        os_elem = host_elem.find("os")
        if os_elem is not None:
            osmatch = os_elem.find("osmatch")
            if osmatch is not None:
                os_name = osmatch.get("name")

        ports: list[PortEntry] = []
        ports_elem = host_elem.find("ports")
        if ports_elem is not None:
            for port_elem in ports_elem.findall("port"):
                port_id   = int(port_elem.get("portid", "0"))
                protocol  = port_elem.get("protocol", "tcp")
                state_elem = port_elem.find("state")
                state     = state_elem.get("state", "unknown") if state_elem is not None else "unknown"

                service_elem = port_elem.find("service")
                service = product = version = extrainfo = cpe = None
                if service_elem is not None:
                    service   = service_elem.get("name", "") or None
                    product   = service_elem.get("product") or None
                    version   = service_elem.get("version") or None
                    extrainfo = service_elem.get("extrainfo") or None
                    cpe_elem  = service_elem.find("cpe")
                    if cpe_elem is not None and cpe_elem.text:
                        cpe = cpe_elem.text

                ports.append(PortEntry(
                    port=port_id, protocol=protocol, state=state,
                    service=service or "", product=product, version=version,
                    extrainfo=extrainfo, cpe=cpe,
                ))

        hosts.append(HostEntry(
            address=address, hostname=hostname, status=status, os=os_name, ports=ports,
        ))

    return hosts


async def run_scan(scan_id: str, target: str, args: str) -> None:
    scan = SCANS[scan_id]
    scan["status"] = "running"
    scan["started_at"] = utcnow()

    cmd = ["nmap", "-oX", "-"]
    if args:
        cmd.extend(re.split(r"\s+", args.strip()))
    cmd.append(target)
    scan["command"] = " ".join(cmd)

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        scan["_proc"] = proc
        stdout, stderr = await proc.communicate()

        raw = stdout.decode("utf-8", errors="replace")
        err = stderr.decode("utf-8", errors="replace")
        scan["raw"] = raw + ("\n\n=== STDERR ===\n" + err if err else "")

        if proc.returncode != 0 and not raw.strip():
            scan["status"] = "failed"
            scan["error"]  = err or f"nmap exited with code {proc.returncode}"
        else:
            scan["hosts"]  = [h.model_dump() for h in parse_nmap_xml(raw)]
            scan["status"] = "completed"

    except FileNotFoundError:
        scan["status"] = "failed"
        scan["error"]  = "nmap not found — install nmap and ensure it is in $PATH"
    except Exception as exc:
        scan["status"] = "failed"
        scan["error"]  = str(exc)
    finally:
        scan["finished_at"] = utcnow()
        scan.pop("_proc", None)


# ─── Endpoints ───────────────────────────────────────────────────────────────

@app.post("/scans", response_model=ScanResponse, status_code=202)
async def start_scan(
    body: StartScanRequest,
    x_auth_token: str | None = Header(default=None, alias="X-Auth-Token"),
):
    require_auth(x_auth_token)
    scan_id = str(uuid.uuid4())
    SCANS[scan_id] = {
        "id": scan_id, "target": body.target, "args": body.args,
        "status": "queued", "started_at": utcnow(), "finished_at": None,
        "command": None, "error": None, "hosts": [], "raw": None,
    }
    asyncio.create_task(run_scan(scan_id, body.target, body.args))
    return ScanResponse(**SCANS[scan_id])


@app.get("/scans", response_model=list[ScanResponse])
async def list_scans(
    x_auth_token: str | None = Header(default=None, alias="X-Auth-Token"),
):
    require_auth(x_auth_token)
    return [ScanResponse(**s) for s in sorted(SCANS.values(), key=lambda x: x["started_at"], reverse=True)]


@app.get("/scans/{scan_id}", response_model=ScanResponse)
async def get_scan(
    scan_id: str,
    x_auth_token: str | None = Header(default=None, alias="X-Auth-Token"),
):
    require_auth(x_auth_token)
    if scan_id not in SCANS:
        raise HTTPException(status_code=404, detail="Scan not found")
    return ScanResponse(**SCANS[scan_id])


@app.post("/scans/{scan_id}/cancel")
async def cancel_scan(
    scan_id: str,
    x_auth_token: str | None = Header(default=None, alias="X-Auth-Token"),
):
    require_auth(x_auth_token)
    if scan_id not in SCANS:
        raise HTTPException(status_code=404, detail="Scan not found")
    scan = SCANS[scan_id]
    proc = scan.get("_proc")
    if proc and proc.returncode is None:
        proc.kill()
        await proc.wait()
    scan["status"] = "failed"
    scan["error"]  = "Cancelled by user"
    scan["finished_at"] = utcnow()
    return {"detail": "Cancelled"}


@app.delete("/scans/{scan_id}")
async def delete_scan(
    scan_id: str,
    x_auth_token: str | None = Header(default=None, alias="X-Auth-Token"),
):
    require_auth(x_auth_token)
    if scan_id not in SCANS:
        raise HTTPException(status_code=404, detail="Scan not found")
    scan = SCANS.pop(scan_id)
    proc = scan.get("_proc")
    if proc and proc.returncode is None:
        proc.kill()
        await proc.wait()
    return {"detail": "Deleted"}


@app.get("/health")
async def health():
    nmap_ok = subprocess.run(["which", "nmap"], capture_output=True).returncode == 0
    return {
        "status": "ok",
        "nmap_available": nmap_ok,
        "auth_enabled": bool(AUTH_TOKEN),
        "scan_count": len(SCANS),
    }


# ─── Entrypoint ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import uvicorn
    print(f"\n  Nmap Web Dashboard — Backend")
    print(f"  Listening on  http://0.0.0.0:{PORT}")
    print(f"  Auth token:   {'enabled' if AUTH_TOKEN else 'disabled (set NMAP_AUTH_TOKEN to enable)'}")
    print(f"  nmap path:    {subprocess.run(['which', 'nmap'], capture_output=True, text=True).stdout.strip() or 'NOT FOUND'}\n")
    uvicorn.run(app, host="0.0.0.0", port=PORT)
