"""Router admin data: consolidated info, snapshots and settings."""
from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..db import BlocklistEntry, Curfew, Device, Policy, RouterSnapshot, TrafficSample, get_session
from ..services import nettools
from ..state import STATE

router = APIRouter(prefix="/api/admin", tags=["admin"])


class SettingsIn(BaseModel):
    router_host: str | None = None
    router_user: str | None = None
    router_vendor: str | None = None
    dry_run: bool | None = None
    api_token: str | None = None
    sample_interval_seconds: int | None = None
    default_ping_target: str | None = None


@router.get("/info")
def admin_info(session: Session = Depends(get_session)) -> dict[str, Any]:
    """Everything a router admin page usually shows, in one payload."""
    router_data: dict[str, Any]
    try:
        st = STATE.router.status() if STATE.router else None
        router_data = {
            "reachable": bool(st),
            "model": st.model if st else None,
            "firmware": st.firmware if st else None,
            "hostname": st.hostname if st else None,
            "uptime_seconds": st.uptime_seconds if st else None,
            "cpu_percent": st.cpu_percent if st else None,
            "mem_percent": st.mem_percent if st else None,
            "mem_total_kb": st.mem_total_kb if st else None,
            "mem_available_kb": st.mem_available_kb if st else None,
            "load_avg": st.load_avg if st else [],
            "wan_ip": st.wan_ip if st else None,
            "wan_gateway": st.wan_gateway if st else None,
            "dns_servers": st.dns_servers if st else [],
            "lan_ip": st.lan_ip if st else None,
            "dhcp_pool": st.dhcp_pool if st else None,
            "wireless": st.wireless if st else [],
            "raw": st.raw if st else {},
        }
    except Exception as exc:
        router_data = {"reachable": False, "error": str(exc)}

    counts = {
        "devices": session.scalar(select(func.count()).select_from(Device)) or 0,
        "blocked_devices": session.scalar(select(func.count()).select_from(Device).where(Device.is_blocked.is_(True))) or 0,
        "safe_mode_devices": session.scalar(select(func.count()).select_from(Device).where(Device.is_safe_mode.is_(True))) or 0,
        "policies": session.scalar(select(func.count()).select_from(Policy)) or 0,
        "curfews": session.scalar(select(func.count()).select_from(Curfew)) or 0,
        "blocklist": session.scalar(select(func.count()).select_from(BlocklistEntry)) or 0,
        "samples": session.scalar(select(func.count()).select_from(TrafficSample)) or 0,
    }
    return {
        "router": router_data,
        "counts": counts,
        "server_time": datetime.now(timezone.utc).isoformat(),
        "version": _version(),
    }


def _version() -> str:
    from .. import __version__

    return __version__


@router.post("/snapshot")
def create_snapshot(session: Session = Depends(get_session)) -> dict[str, Any]:
    if STATE.router is None:
        raise HTTPException(status_code=503, detail="no router configured")
    try:
        st = STATE.router.status()
        clients = STATE.router.clients()
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"router unreachable: {exc}")
    payload = {
        "status": {
            "model": st.model,
            "firmware": st.firmware,
            "uptime_seconds": st.uptime_seconds,
            "wan_ip": st.wan_ip,
            "dns_servers": st.dns_servers,
            "load_avg": st.load_avg,
            "mem_percent": st.mem_percent,
        },
        "clients": [{"mac": c.mac, "ip": c.ip, "hostname": c.hostname} for c in clients],
        "captured_at": datetime.now(timezone.utc).isoformat(),
    }
    snapshot = RouterSnapshot(payload=json.dumps(payload))
    session.add(snapshot)
    session.flush()
    return {"id": snapshot.id, "ts": snapshot.ts.isoformat()}


@router.get("/snapshots")
def list_snapshots(limit: int = 50, session: Session = Depends(get_session)) -> dict[str, Any]:
    rows = session.scalars(select(RouterSnapshot).order_by(RouterSnapshot.ts.desc()).limit(limit)).all()
    return {
        "snapshots": [
            {"id": s.id, "ts": s.ts.isoformat() if s.ts else None, "payload": json.loads(s.payload)}
            for s in rows
        ]
    }


@router.get("/settings")
def get_settings() -> dict[str, Any]:
    cfg = STATE.config
    return {
        "router": {
            "vendor": cfg.router.vendor,
            "host": cfg.router.host,
            "port": cfg.router.port,
            "user": cfg.router.user,
            "wan_interface": cfg.router.wan_interface,
            "lan_interface": cfg.router.lan_interface,
            "dnsmasq_hosts_file": cfg.router.dnsmasq_hosts_file,
            "dry_run": cfg.router.dry_run,
        },
        "filtering": {
            "enabled": cfg.filtering.enabled,
            "default_block_categories": cfg.filtering.default_block_categories,
            "allowlist_domains": cfg.filtering.allowlist_domains,
        },
        "monitoring": {
            "sample_interval_seconds": cfg.monitoring.sample_interval_seconds,
            "retention_days": cfg.monitoring.retention_days,
            "speedtest_enabled": cfg.monitoring.speedtest_enabled,
            "default_ping_target": cfg.monitoring.default_ping_target,
        },
        "storage": {"data_dir": str(cfg.data_path)},
        "api_token_set": bool(cfg.api_token),
        "demo_mode": cfg.demo_mode,
    }


@router.put("/settings")
def update_settings(payload: SettingsIn) -> dict[str, Any]:
    cfg = STATE.config
    if payload.router_host:
        cfg.router.host = payload.router_host
    if payload.router_user:
        cfg.router.user = payload.router_user
    if payload.router_vendor:
        cfg.router.vendor = payload.router_vendor
    if payload.dry_run is not None:
        cfg.router.dry_run = payload.dry_run
    if payload.api_token is not None:
        cfg.api_token = payload.api_token
    if payload.sample_interval_seconds:
        cfg.monitoring.sample_interval_seconds = payload.sample_interval_seconds
    if payload.default_ping_target:
        cfg.monitoring.default_ping_target = payload.default_ping_target
    return {"status": "updated", "settings": get_settings()}


@router.get("/health")
def health() -> dict[str, Any]:
    reachable = False
    try:
        reachable = bool(STATE.router and STATE.router.reachable())
    except Exception:
        reachable = False
    return {"status": "ok", "router_reachable": reachable, "version": _version()}


@router.get("/tools")
def tools() -> dict[str, Any]:
    """Capability report for the tools this host can use."""
    import shutil

    return {
        "ping": bool(shutil.which("ping")),
        "traceroute": bool(shutil.which("traceroute")),
        "speedtest_cli": bool(shutil.which("speedtest-cli")),
        "ssh": bool(shutil.which("ssh")),
        "sshpass": bool(shutil.which("sshpass")),
        "http_speedtest": True,
        "playwright": _module_available("playwright"),
        "pillow": _module_available("PIL"),
    }


def _module_available(name: str) -> bool:
    import importlib.util

    try:
        return importlib.util.find_spec(name) is not None
    except Exception:
        return False
