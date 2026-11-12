"""Network monitoring: router status, traffic samples and diagnostic tools."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..db import Device, TrafficSample, get_session
from ..services import nettools
from ..state import STATE

router = APIRouter(prefix="/api/network", tags=["network"])

_last_counters: dict[str, tuple[int, int]] = {}


class HostRequest(BaseModel):
    host: str
    count: int = 4
    timeout: int = 10


class ScanRequest(BaseModel):
    cidr: str = "192.168.1.0/24"
    timeout: float = 0.25


class PortScanRequest(BaseModel):
    host: str
    ports: list[int] | None = None


def _router_status() -> dict[str, Any]:
    if STATE.router is None:
        raise HTTPException(status_code=503, detail="no router configured")
    try:
        st = STATE.router.status()
    except Exception as exc:
        return {"error": str(exc), "reachable": False}
    return {
        "reachable": True,
        "model": st.model,
        "firmware": st.firmware,
        "hostname": st.hostname,
        "uptime_seconds": st.uptime_seconds,
        "load_avg": st.load_avg,
        "cpu_percent": st.cpu_percent,
        "mem_percent": st.mem_percent,
        "mem_total_kb": st.mem_total_kb,
        "mem_available_kb": st.mem_available_kb,
        "wan_ip": st.wan_ip,
        "wan_gateway": st.wan_gateway,
        "dns_servers": st.dns_servers,
        "lan_ip": st.lan_ip,
        "dhcp_pool": st.dhcp_pool,
        "wireless": st.wireless,
        "raw": st.raw,
    }


@router.get("/status")
def network_status() -> dict[str, Any]:
    data = _router_status()
    interfaces = nettools.local_interfaces()
    data["local_interfaces"] = interfaces.detail
    data["collected_at"] = datetime.now(timezone.utc).isoformat()
    return data


@router.post("/collect")
def collect_sample(session: Session = Depends(get_session)) -> dict[str, Any]:
    """Take a traffic / load snapshot from the router and store it."""
    if STATE.router is None:
        raise HTTPException(status_code=503, detail="no router configured")
    status = _router_status()
    traffic_text = (status.get("raw") or {}).get("traffic", "") or ""

    counters: dict[str, tuple[int, int]] = {}
    for line in traffic_text.splitlines():
        if ":" not in line:
            continue
        name, _, rest = line.partition(":")
        parts = rest.split()
        if len(parts) >= 9:
            try:
                counters[name.strip()] = (int(parts[0]), int(parts[8]))
            except ValueError:
                continue

    total_rx = sum(rx for rx, _ in counters.values())
    total_tx = sum(tx for _, tx in counters.values())
    prev_rx, prev_tx = _last_counters.get("__total__", (0, 0))
    _last_counters["__total__"] = (total_rx, total_tx)
    delta_rx = max(total_rx - prev_rx, 0)
    delta_tx = max(total_tx - prev_tx, 0)

    sample = TrafficSample(
        device_id=None,
        rx_bytes=delta_rx,
        tx_bytes=delta_tx,
        cpu_percent=status.get("cpu_percent"),
        mem_percent=status.get("mem_percent"),
        load_avg=(status.get("load_avg") or [None])[0],
    )
    session.add(sample)
    session.flush()

    # per-device counters where the router exposes them (mock / openwrt leases)
    try:
        for client in STATE.router.clients():
            device = session.scalars(select(Device).where(Device.mac == client.mac)).first()
            if not device:
                continue
            previous = _last_counters.get(client.mac)
            _last_counters[client.mac] = (client.rx_bytes, client.tx_bytes)
            if previous:
                session.add(
                    TrafficSample(
                        device_id=device.id,
                        rx_bytes=max(client.rx_bytes - previous[0], 0),
                        tx_bytes=max(client.tx_bytes - previous[1], 0),
                    )
                )
    except Exception:
        pass

    session.flush()
    return {
        "sample_id": sample.id,
        "rx_bytes": delta_rx,
        "tx_bytes": delta_tx,
        "cpu_percent": status.get("cpu_percent"),
        "mem_percent": status.get("mem_percent"),
        "load_avg": status.get("load_avg"),
    }


@router.get("/traffic")
def traffic_series(hours: int = 24, session: Session = Depends(get_session)) -> dict[str, Any]:
    since = datetime.now(timezone.utc) - timedelta(hours=hours)
    rows = session.scalars(
        select(TrafficSample).where(TrafficSample.ts >= since).order_by(TrafficSample.ts)
    ).all()
    return {
        "count": len(rows),
        "samples": [
            {
                "ts": s.ts.isoformat() if s.ts else None,
                "device_id": s.device_id,
                "rx_bytes": s.rx_bytes,
                "tx_bytes": s.tx_bytes,
                "latency_ms": s.latency_ms,
                "cpu_percent": s.cpu_percent,
                "mem_percent": s.mem_percent,
                "load_avg": s.load_avg,
            }
            for s in rows
        ],
    }


@router.get("/summary")
def traffic_summary(hours: int = 24, session: Session = Depends(get_session)) -> dict[str, Any]:
    since = datetime.now(timezone.utc) - timedelta(hours=hours)
    rows = session.scalars(select(TrafficSample).where(TrafficSample.ts >= since)).all()
    rx = sum(s.rx_bytes for s in rows)
    tx = sum(s.tx_bytes for s in rows)
    per_device: dict[int, dict[str, int]] = {}
    for s in rows:
        if s.device_id is None:
            continue
        entry = per_device.setdefault(s.device_id, {"rx_bytes": 0, "tx_bytes": 0})
        entry["rx_bytes"] += s.rx_bytes
        entry["tx_bytes"] += s.tx_bytes
    devices = {d.id: d for d in session.scalars(select(Device)).all()}
    ranked = sorted(
        (
            {
                "device_id": did,
                "name": devices[did].friendly_name or devices[did].hostname or devices[did].mac,
                **values,
            }
            for did, values in per_device.items()
            if did in devices
        ),
        key=lambda row: row["rx_bytes"] + row["tx_bytes"],
        reverse=True,
    )
    return {
        "window_hours": hours,
        "total_rx_bytes": rx,
        "total_tx_bytes": tx,
        "per_device": ranked,
    }


@router.post("/ping")
def ping(payload: HostRequest) -> dict[str, Any]:
    result = nettools.ping(payload.host, payload.count, payload.timeout)
    return {"ok": result.ok, "output": result.output, "detail": result.detail}


@router.post("/traceroute")
def traceroute(payload: HostRequest) -> dict[str, Any]:
    result = nettools.traceroute(payload.host, timeout=payload.timeout + 30)
    return {"ok": result.ok, "output": result.output, "detail": result.detail}


@router.post("/speedtest")
def speedtest() -> dict[str, Any]:
    result = nettools.speedtest(STATE.config.monitoring.speedtest_timeout)
    return {"ok": result.ok, "output": result.output, "detail": result.detail}


@router.post("/dns")
def dns(payload: HostRequest) -> dict[str, Any]:
    result = nettools.dns_lookup(payload.host)
    return {"ok": result.ok, "output": result.output, "detail": result.detail}


@router.post("/scan")
def scan(payload: ScanRequest) -> dict[str, Any]:
    result = nettools.scan_subnet(payload.cidr, payload.timeout)
    return {"ok": result.ok, "output": result.output, "detail": result.detail}


@router.post("/portscan")
def portscan(payload: PortScanRequest) -> dict[str, Any]:
    result = nettools.port_scan(payload.host, payload.ports)
    return {"ok": result.ok, "output": result.output, "detail": result.detail}


@router.get("/arp")
def arp() -> dict[str, Any]:
    result = nettools.local_arp_table()
    return {"ok": result.ok, "output": result.output, "detail": result.detail}
