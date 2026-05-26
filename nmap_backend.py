#!/usr/bin/env python3
"""
Nmap Web Backend — FastAPI service that wraps nmap scans.

Provides HTTP endpoints to:
  - Start scans   POST /scans
  - List scans    GET  /scans
  - Get scan      GET  /scans/{id}
  - Cancel scan   POST /scans/{id}/cancel
  - Delete scan   DELETE /scans/{id}

Run with:
    pip install fastapi uvicorn
    sudo python nmap_backend.py

Root (sudo) is required for SYN (-sS), UDP (-sU), and OS detection (-O) scans.
"""

import asyncio
import json
import os
import re
import subprocess
import uuid
from datetime import datetime
from typing import Any

from fastapi import FastAPI, HTTPException, Header
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import xml.etree.ElementTree as ET

# ─── Config ──────────────────────────────────────────────────────────────────

AUTH_TOKEN = os.environ.get("NMAP_AUTH_TOKEN", "")
PORT = int(os.environ.get("NMAP_BACKEND_PORT", "8765"))

# In-memory store (replace with Redis/DB for multi-process)
SCANS: dict[str, dict] = {}

app = FastAPI(title="Nmap Web Backend", version="1.0.0")

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

def _require_auth(x_auth_token: str | None) -> None:
    if AUTH_TOKEN and x_auth_token != AUTH_TOKEN:
        raise HTTPException(status_code=401, detail="Invalid or missing auth token")


def _parse_nmap_xml(xml_text: str) -> list[HostEntry]:
    hosts: list[HostEntry] = []
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return hosts

    for host_elem in root.findall("host"):
        addr_elem = host_elem.find("address")
        address = addr_elem.get("addr", "") if addr_elem is not None else ""

        hostnames_elem = host_elem.find("hostnames")
        hostname = None
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
                port_id = int(port_elem.get("portid", "0"))
                protocol = port_elem.get("protocol", "tcp")
                state_elem = port_elem.find("state")
                state = state_elem.get("state", "unknown") if state_elem is not None else "unknown"

                service_elem = port_elem.find("service")
                service = ""
                product = version = extrainfo = cpe = None
                if service_elem is not None:
                    service = service_elem.get("name", "")
                    product = service_elem.get("product") or None
                    version = service_elem.get("version") or None
                    extrainfo = service_elem.get("extrainfo") or None
                    cpe_elem = service_elem.find("cpe")
                    if cpe_elem is not None and cpe_elem.text:
                        cpe = cpe_elem.text

                ports.append(PortEntry(
                    port=port_id,
                    protocol=protocol,
                    state=state,
                    service=service,
                    product=product,
                    version=version,
                    extrainfo=extrainfo,
                    cpe=cpe,
                ))

        hosts.append(HostEntry(
            address=address,
            hostname=hostname,
            status=status,
            os=os_name,
            ports=ports,
        ))

    return hosts


async def _run_scan(scan_id: str, target: str, args: str) -> None:
    scan = SCANS[scan_id]
    scan["status"] = "running"
    scan["started_at"] = datetime.utcnow().isoformat()

    # Build command
    cmd_parts = ["nmap", "-oX", "-"]
    if args:
        # Split args safely — basic shell-like split
        cmd_parts.extend(re.split(r"\s+", args.strip()))
    cmd_parts.append(target)
    scan["command"] = " ".join(cmd_parts)

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd_parts,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        scan["_proc"] = proc
        stdout, stderr = await proc.communicate()

        raw_out = stdout.decode("utf-8", errors="replace")
        err_out = stderr.decode("utf-8", errors="replace")

        scan["raw"] = raw_out
        if err_out:
            scan["raw"] += "\n\n=== STDERR ===\n" + err_out

        if proc.returncode != 0 and not raw_out.strip():
            scan["status"] = "failed"
            scan["error"] = err_out or f"nmap exited with code {proc.returncode}"
        else:
            hosts = _parse_nmap_xml(raw_out)
            scan["hosts"] = [h.model_dump() for h in hosts]
            scan["status"] = "completed"

    except FileNotFoundError:
        scan["status"] = "failed"
        scan["error"] = "nmap not found. Install nmap first."
    except Exception as exc:
        scan["status"] = "failed"
        scan["error"] = str(exc)
    finally:
        scan["finished_at"] = datetime.utcnow().isoformat()
        scan.pop("_proc", None)


# ─── Endpoints ───────────────────────────────────────────────────────────────

@app.post("/scans", response_model=ScanResponse, status_code=202)
async def start_scan(
    body: StartScanRequest,
    x_auth_token: str | None = Header(default=None, alias="X-Auth-Token"),
):
    _require_auth(x_auth_token)
    scan_id = str(uuid.uuid4())
    SCANS[scan_id] = {
        "id": scan_id,
        "target": body.target,
        "args": body.args,
        "status": "queued",
        "started_at": datetime.utcnow().isoformat(),
        "finished_at": None,
        "command": None,
        "error": None,
        "hosts": [],
        "raw": None,
    }
    asyncio.create_task(_run_scan(scan_id, body.target, body.args))
    return ScanResponse(**SCANS[scan_id])


@app.get("/scans", response_model=list[ScanResponse])
async def list_scans(
    x_auth_token: str | None = Header(default=None, alias="X-Auth-Token"),
):
    _require_auth(x_auth_token)
    return [ScanResponse(**s) for s in sorted(SCANS.values(), key=lambda x: x["started_at"], reverse=True)]


@app.get("/scans/{scan_id}", response_model=ScanResponse)
async def get_scan(
    scan_id: str,
    x_auth_token: str | None = Header(default=None, alias="X-Auth-Token"),
):
    _require_auth(x_auth_token)
    if scan_id not in SCANS:
        raise HTTPException(status_code=404, detail="Scan not found")
    return ScanResponse(**SCANS[scan_id])


@app.post("/scans/{scan_id}/cancel")
async def cancel_scan(
    scan_id: str,
    x_auth_token: str | None = Header(default=None, alias="X-Auth-Token"),
):
    _require_auth(x_auth_token)
    if scan_id not in SCANS:
        raise HTTPException(status_code=404, detail="Scan not found")
    scan = SCANS[scan_id]
    proc = scan.get("_proc")
    if proc and proc.returncode is None:
        proc.kill()
        await proc.wait()
    scan["status"] = "failed"
    scan["error"] = "Cancelled by user"
    scan["finished_at"] = datetime.utcnow().isoformat()
    return {"detail": "Cancelled"}


@app.delete("/scans/{scan_id}")
async def delete_scan(
    scan_id: str,
    x_auth_token: str | None = Header(default=None, alias="X-Auth-Token"),
):
    _require_auth(x_auth_token)
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
    return {"status": "ok", "nmap_available": subprocess.run(["which", "nmap"], capture_output=True).returncode == 0}


# ─── Entrypoint ────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import uvicorn
    print(f"Starting Nmap Web Backend on port {PORT}")
    if AUTH_TOKEN:
        print("Auth token is enabled")
    else:
        print("No auth token configured — set NMAP_AUTH_TOKEN env var to enable")
    uvicorn.run(app, host="0.0.0.0", port=PORT)
