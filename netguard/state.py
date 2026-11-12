"""Shared application state: config, router client and business helpers."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from .config import AppConfig, load_config
from .db import Device, init_engine
from .services.router import BaseRouter, RouterDevice, build_router

OUI_VENDORS: dict[str, str] = {
    "00:1A:11": "Google",
    "3C:5A:B4": "Google",
    "F4:F5:E8": "Google",
    "F0:18:98": "Apple",
    "A4:5E:60": "Apple",
    "AC:BC:32": "Apple",
    "00:1E:75": "Apple",
    "8C:85:90": "Apple",
    "78:4F:43": "Apple",
    "00:16:3E": "Samsung",
    "78:1F:DB": "Samsung",
    "E0:E1:5C": "Samsung",
    "5C:0A:5B": "Samsung",
    "00:15:99": "Samsung",
    "D0:03:4F": "Samsung",
    "00:1C:42": "Parallels",
    "00:50:56": "VMware",
    "08:00:27": "VirtualBox",
    "00:24:9B": "Sony",
    "FC:EC:DA": "Ubiquiti",
    "74:83:C2": "Ubiquiti",
    "24:A4:3C": "Ubiquiti",
    "00:04:42": "Routerboard/MikroTik",
    "E4:8D:8C": "Routerboard/MikroTik",
    "B8:27:EB": "Raspberry Pi",
    "DC:A6:32": "Raspberry Pi",
    "E4:5F:01": "Raspberry Pi",
    "00:1D:7E": "Cisco-Linksys",
    "00:0C:29": "VMware",
    "00:1B:63": "Apple",
    "10:32:7B": "TP-Link",
    "50:C7:BF": "TP-Link",
    "C0:25:E9": "TP-Link",
    "EC:08:6B": "TP-Link",
    "00:1C:C0": "Intel",
    "3C:97:0E": "Intel",
    "94:65:9C": "Intel",
}


def detect_vendor(mac: str) -> str | None:
    prefix = (mac or "").upper().replace("-", ":")[:8]
    return OUI_VENDORS.get(prefix)


def detect_device_type(hostname: str | None, vendor: str | None) -> str:
    name = (hostname or "").lower()
    vendor_l = (vendor or "").lower()
    if any(k in name for k in ("phone", "iphone", "android", "pixel", "galaxy", "samsung", "mobile")):
        return "phone"
    if any(k in name for k in ("ipad", "tablet", "kindle")):
        return "tablet"
    if any(k in name for k in ("tv", "chromecast", "firetv", "roku", "firestick")):
        return "tv"
    if any(k in name for k in ("laptop", "macbook", "desktop", "pc", "workstation", "imac")):
        return "pc"
    if any(k in name for k in ("echo", "alexa", "nest", "sonos", "camera", "cam", "doorbell", "printer", "chromebit")):
        return "iot"
    if "apple" in vendor_l:
        return "phone"
    if "raspberry" in vendor_l:
        return "iot"
    return "unknown"


@dataclass
class AppState:
    config: AppConfig = field(default_factory=AppConfig)
    router: BaseRouter | None = None
    started_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def boot(self) -> None:
        self.config = load_config()
        init_engine(self.config.sqlalchemy_url)
        if self.config.demo_mode:
            from .services.router import MockRouter

            self.router = MockRouter(self.config.router)
        else:
            self.router = build_router(self.config.router)


STATE = AppState()


# ---------------------------------------------------------------- helpers
def sync_devices(session: Session, router_devices: list[RouterDevice]) -> list[Device]:
    """Merge router data into the local device inventory."""
    known = {d.mac.upper(): d for d in session.scalars(select(Device)).all()}
    result: list[Device] = []
    now = datetime.now(timezone.utc)
    for rd in router_devices:
        mac = rd.mac.upper()
        device = known.get(mac)
        if device is None:
            device = Device(mac=mac, first_seen=now)
            session.add(device)
        device.ip = rd.ip or device.ip
        device.hostname = rd.hostname or device.hostname
        device.vendor = device.vendor or detect_vendor(mac)
        device.device_type = detect_device_type(device.hostname, device.vendor)
        device.last_seen = now
        result.append(device)
    session.flush()
    return result


def device_to_dict(device: Device) -> dict[str, Any]:
    return {
        "id": device.id,
        "mac": device.mac,
        "ip": device.ip,
        "hostname": device.hostname,
        "friendly_name": device.friendly_name or device.hostname,
        "vendor": device.vendor,
        "device_type": device.device_type,
        "notes": device.notes,
        "photo_path": device.photo_path,
        "is_blocked": device.is_blocked,
        "is_safe_mode": device.is_safe_mode,
        "is_quarantined": device.is_quarantined,
        "first_seen": device.first_seen.isoformat() if device.first_seen else None,
        "last_seen": device.last_seen.isoformat() if device.last_seen else None,
    }
