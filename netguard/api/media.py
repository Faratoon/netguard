"""Image management endpoints (device photos, screenshots, topology maps)."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile
from fastapi.responses import FileResponse, Response
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..db import Device, ImageAsset, get_session
from ..services import media
from ..state import STATE

router = APIRouter(prefix="/api/media", tags=["media"])


class ScreenshotRequest(BaseModel):
    url: str
    device_id: int | None = None
    title: str | None = None


@router.post("/upload", status_code=201)
async def upload(
    file: UploadFile = File(...),
    kind: str = Form("device_photo"),
    device_id: int | None = Form(None),
    title: str | None = Form(None),
    session: Session = Depends(get_session),
) -> dict[str, Any]:
    data = await file.read()
    try:
        stored = media.save_image(data, STATE.config.media_path, file.filename, kind, title)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))

    asset = ImageAsset(
        filename=stored.filename,
        kind=stored.kind,
        title=stored.title or stored.filename,
        related_id=device_id,
    )
    session.add(asset)
    session.flush()

    if device_id:
        device = session.get(Device, device_id)
        if device and stored.kind == "device_photo":
            device.photo_path = stored.filename

    return {
        "id": asset.id,
        "filename": stored.filename,
        "kind": stored.kind,
        "width": stored.width,
        "height": stored.height,
        "url": f"/api/media/file/{stored.filename}",
        "thumbnail_url": f"/api/media/file/thumb-{stored.filename}",
    }


@router.get("/list")
def list_assets(kind: str | None = None, session: Session = Depends(get_session)) -> dict[str, Any]:
    stmt = select(ImageAsset)
    if kind:
        stmt = stmt.where(ImageAsset.kind == kind)
    rows = session.scalars(stmt.order_by(ImageAsset.id.desc())).all()
    return {
        "assets": [
            {
                "id": a.id,
                "filename": a.filename,
                "kind": a.kind,
                "title": a.title,
                "related_id": a.related_id,
                "created_at": a.created_at.isoformat() if a.created_at else None,
                "url": f"/api/media/file/{a.filename}",
            }
            for a in rows
        ]
    }


@router.get("/file/{filename}")
def get_file(filename: str):
    path = STATE.config.media_path / filename
    if not path.exists():
        raise HTTPException(status_code=404, detail="image not found")
    media_type = "image/png" if path.suffix.lower() in {".png", ".jpg", ".jpeg"} else None
    return FileResponse(path, media_type=media_type)


@router.delete("/file/{filename}")
def delete_file(filename: str, session: Session = Depends(get_session)) -> dict[str, str]:
    removed = media.delete_image(STATE.config.media_path, filename)
    asset = session.scalars(select(ImageAsset).where(ImageAsset.filename == filename)).first()
    if asset:
        session.delete(asset)
    return {"status": "deleted" if removed else "not found"}


@router.get("/topology.svg")
def topology(session: Session = Depends(get_session)) -> Response:
    devices = session.scalars(select(Device)).all()
    router_info = {}
    if STATE.router:
        try:
            st = STATE.router.status()
            router_info = {"model": st.model, "firmware": st.firmware, "wan_ip": st.wan_ip}
        except Exception:
            router_info = {}
    svg = media.build_topology_svg(
        [
            {
                "hostname": d.hostname,
                "friendly_name": d.friendly_name,
                "ip": d.ip,
                "mac": d.mac,
                "is_blocked": d.is_blocked,
                "is_quarantined": d.is_quarantined,
            }
            for d in devices
        ],
        router_info,
    )
    return Response(content=svg, media_type="image/svg+xml")


@router.post("/screenshot", status_code=201)
def screenshot(payload: ScreenshotRequest, session: Session = Depends(get_session)) -> dict[str, Any]:
    """Capture what a blocked page looks like (needs playwright)."""
    data = media.capture_blocked_page(payload.url)
    if not data:
        raise HTTPException(
            status_code=503,
            detail="playwright is not installed - run 'pip install playwright && playwright install chromium'",
        )
    stored = media.save_image(data, STATE.config.media_path, "blocked-page.png", "blocked_page", payload.title)
    asset = ImageAsset(
        filename=stored.filename,
        kind="blocked_page",
        title=payload.title or payload.url,
        related_id=payload.device_id,
    )
    session.add(asset)
    session.flush()
    return {"id": asset.id, "filename": stored.filename, "url": f"/api/media/file/{stored.filename}"}


@router.post("/topology/save")
def save_topology(session: Session = Depends(get_session)) -> dict[str, Any]:
    devices = session.scalars(select(Device)).all()
    svg = media.build_topology_svg(
        [{"hostname": d.hostname, "friendly_name": d.friendly_name, "ip": d.ip, "is_blocked": d.is_blocked} for d in devices],
        {},
    )
    stored = media.save_image(svg, STATE.config.media_path, "topology.svg", "topology", "Network topology")
    asset = ImageAsset(filename=stored.filename, kind="topology", title="Network topology")
    session.add(asset)
    session.flush()
    return {"id": asset.id, "filename": stored.filename, "url": f"/api/media/file/{stored.filename}"}
