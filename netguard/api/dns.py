"""DNS filter endpoints: status, control and a lookup tester."""
from __future__ import annotations

import socket
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from ..db import get_session
from ..services.dnsfilter import DnsFilterServer
from ..state import STATE

router = APIRouter(prefix="/api/dns", tags=["dns"])


class LookupRequest(BaseModel):
    domain: str
    client_ip: str = "192.168.1.50"


class DnsSettingsIn(BaseModel):
    enabled: bool | None = None
    host: str | None = None
    port: int | None = None
    upstream: list[str] | None = None


def _server() -> DnsFilterServer | None:
    return STATE.dns_filter


@router.get("/status")
def dns_status() -> dict[str, Any]:
    server = _server()
    cfg = STATE.config.dns_filter
    payload: dict[str, Any] = {
        "enabled": cfg.enabled,
        "host": cfg.host,
        "port": cfg.port,
        "upstream": cfg.upstream,
        "running": bool(server and server._threads),
        "error": server.error if server else None,
        "listen": _local_ips(),
    }
    if server and server._threads:
        payload["stats"] = server.stats.as_dict()
    return payload


def _local_ips() -> list[str]:
    ips: list[str] = []
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
            ip = info[4][0]
            if not ip.startswith("127."):
                ips.append(ip)
    except OSError:
        pass
    return sorted(set(ips))


@router.post("/start")
def dns_start() -> dict[str, Any]:
    if _server() is None:
        raise HTTPException(status_code=503, detail="dns filter not initialised")
    server = _server()
    server.start()
    if not server._threads:
        raise HTTPException(status_code=500, detail=server.error or "could not start dns filter")
    return dns_status()


@router.post("/stop")
def dns_stop() -> dict[str, Any]:
    server = _server()
    if server is None:
        raise HTTPException(status_code=503, detail="dns filter not initialised")
    server.stop()
    return dns_status()


@router.put("/settings")
def dns_settings(payload: DnsSettingsIn) -> dict[str, Any]:
    cfg = STATE.config.dns_filter
    if payload.enabled is not None:
        cfg.enabled = payload.enabled
    if payload.host:
        cfg.host = payload.host
    if payload.port:
        cfg.port = payload.port
    if payload.upstream:
        cfg.upstream = payload.upstream
    server = _server()
    if server:
        server.upstream = cfg.upstream
    try:
        from ..config import save_config

        save_config(STATE.config)
    except Exception:
        pass
    return dns_status()


@router.post("/lookup")
def dns_lookup(payload: LookupRequest, session: Session = Depends(get_session)) -> dict[str, Any]:
    """Test a domain against the filter (no real DNS query is sent)."""
    from ..services.policy import evaluate, find_device_by_ip

    device = find_device_by_ip(session, payload.client_ip)
    decision = evaluate(
        session,
        device,
        domain=payload.domain,
        default_categories=set(STATE.config.filtering.default_block_categories),
    )
    return {
        "domain": payload.domain,
        "client_ip": payload.client_ip,
        "device": (device.friendly_name or device.hostname) if device else None,
        "blocked": decision.blocked,
        "reason": decision.reason,
        "category": decision.category,
        "resolved_to": "0.0.0.0" if decision.blocked else "upstream",
    }


@router.get("/coverage")
def dns_coverage(session: Session = Depends(get_session)) -> dict[str, Any]:
    """Which devices actually use NetGuard's DNS server (= are filtered).

    A device that never queries us is *not* protected, even if rules exist for
    it - so this is the list of phones that still need their DNS changed.
    """
    import time

    from sqlalchemy import select

    from ..db import Device

    server = _server()
    clients = (server.stats.clients if server else {}) or {}
    now = int(time.time())
    devices = session.scalars(select(Device)).all()
    rows = []
    for device in devices:
        info = clients.get(device.ip or "", {})
        last_seen = info.get("last_seen")
        rows.append(
            {
                "device_id": device.id,
                "name": device.friendly_name or device.hostname or device.mac,
                "ip": device.ip,
                "mac": device.mac,
                "device_type": device.device_type,
                "is_safe_mode": device.is_safe_mode,
                "is_blocked": device.is_blocked,
                "filtered": bool(info),
                "queries": info.get("queries", 0),
                "blocked_queries": info.get("blocked", 0),
                "last_seen": last_seen,
                "last_seen_human": (
                    f"{now - last_seen}s ago" if last_seen else "never"
                ),
            }
        )
    rows.sort(key=lambda row: (not row["filtered"], row["name"] or ""))
    return {
        "dns_servers": _local_ips(),
        "devices": rows,
        "filtered": sum(1 for row in rows if row["filtered"]),
        "total": len(rows),
        "unfiltered": [row for row in rows if not row["filtered"]],
    }


@router.get("/instructions")
def dns_instructions() -> dict[str, Any]:
    """Ready-to-follow steps for putting a device behind the DNS filter."""
    server = _server()
    ips = _local_ips()
    primary = ips[0] if ips else "<netguard-ip>"
    port = STATE.config.dns_filter.port
    return {
        "dns_server": f"{primary}:{port}" if port != 53 else primary,
        "steps": [
            "Android: Settings > Wi-Fi > (your network) > Privacy > Private DNS > Off, "
            "then IP settings > Static > DNS = " + primary,
            "iPhone: Settings > Wi-Fi > (i) > Configure DNS > Manual > add " + primary,
            "Windows: Settings > Network & internet > Wi-Fi > DNS assignment > Manual > " + primary,
            "Router-wide: set the DHCP DNS server of your LAN to " + primary,
        ],
        "note": (
            "Every device that uses this DNS server is filtered: blocked domains "
            "resolve to 0.0.0.0 and the attempt is logged in the audit trail."
        ),
        "running": bool(server and server._threads),
    }
