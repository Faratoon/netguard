"""Device inventory endpoints."""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..db import Device, get_session
from ..state import STATE, device_to_dict, sync_devices

router = APIRouter(prefix="/api/devices", tags=["devices"])


class DeviceUpdate(BaseModel):
    friendly_name: str | None = None
    notes: str | None = None
    device_type: str | None = None
    is_blocked: bool | None = None
    is_safe_mode: bool | None = None
    is_quarantined: bool | None = None
    photo_path: str | None = None


def _refresh(session: Session) -> None:
    """Pull the current client list from the router and merge it into the DB."""
    if STATE.router is None:
        return
    try:
        clients = STATE.router.clients()
    except Exception:
        clients = []
    if clients:
        sync_devices(session, clients)


@router.get("")
def list_devices(
    sync: bool = Query(True, description="refresh the inventory from the router first"),
    session: Session = Depends(get_session),
) -> dict[str, Any]:
    if sync:
        _refresh(session)
    devices = session.scalars(select(Device).order_by(Device.last_seen.desc())).all()
    return {"count": len(devices), "devices": [device_to_dict(d) for d in devices]}


@router.post("/scan")
def scan_devices(session: Session = Depends(get_session)) -> dict[str, Any]:
    _refresh(session)
    devices = session.scalars(select(Device)).all()
    return {"count": len(devices), "devices": [device_to_dict(d) for d in devices]}


@router.get("/{device_id}")
def get_device(device_id: int, session: Session = Depends(get_session)) -> dict[str, Any]:
    device = session.get(Device, device_id)
    if not device:
        raise HTTPException(status_code=404, detail="device not found")
    data = device_to_dict(device)
    data["policies"] = [
        {
            "id": p.id,
            "kind": p.kind,
            "value": p.value,
            "action": p.action,
            "category": p.category,
            "enabled": p.enabled,
        }
        for p in device.policies
    ]
    data["curfews"] = [
        {
            "id": c.id,
            "label": c.label,
            "days": c.days,
            "start_time": c.start_time,
            "end_time": c.end_time,
            "action": c.action,
            "enabled": c.enabled,
        }
        for c in device.curfews
    ]
    return data


@router.patch("/{device_id}")
def update_device(device_id: int, payload: DeviceUpdate, session: Session = Depends(get_session)) -> dict[str, Any]:
    device = session.get(Device, device_id)
    if not device:
        raise HTTPException(status_code=404, detail="device not found")
    for field, value in payload.model_dump(exclude_none=True).items():
        setattr(device, field, value)
    session.flush()
    return device_to_dict(device)


@router.delete("/{device_id}")
def delete_device(device_id: int, session: Session = Depends(get_session)) -> dict[str, str]:
    device = session.get(Device, device_id)
    if not device:
        raise HTTPException(status_code=404, detail="device not found")
    session.delete(device)
    return {"status": "deleted"}
