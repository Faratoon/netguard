"""Policy evaluation shared by the REST API and the DNS filter server."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..db import BlocklistEntry, Curfew, Device, Policy
from .rules import MIC_SENSITIVE_APPS, Decision, domain_matches, in_schedule, normalize_domain

SAFE_MODE_CATEGORIES = {"adult", "social", "gaming", "risky"}


def device_categories(device: Device | None, default_categories: set[str] | None = None) -> set[str]:
    cats = set(default_categories or {"adult"})
    if device is not None and device.is_safe_mode:
        cats |= SAFE_MODE_CATEGORIES
    return cats


def evaluate(
    session: Session,
    device: Device | None,
    domain: str | None = None,
    ip: str | None = None,
    app: str | None = None,
    now: datetime | None = None,
    default_categories: set[str] | None = None,
) -> Decision:
    """Decide whether a request must be blocked, and why."""
    now = now or datetime.now(timezone.utc)
    domain = normalize_domain(domain or "")
    targets: list[str] = []
    if domain:
        targets.append(domain)
    if app:
        targets.extend(MIC_SENSITIVE_APPS.get(app.lower(), []))

    policies = session.scalars(select(Policy).where(Policy.enabled.is_(True))).all()

    def applies(policy: Policy) -> bool:
        if policy.device_id is None:
            return True
        return device is not None and policy.device_id == device.id

    # 1) explicit allow rules win
    for policy in policies:
        if policy.action == "allow" and applies(policy):
            if policy.kind == "domain" and any(domain_matches(t, policy.value) for t in targets):
                return Decision(False, f"allow rule #{policy.id}", policy.category, policy.id)
            if policy.kind == "ip" and ip and _ip_match(ip, policy.value):
                return Decision(False, f"allow rule #{policy.id}", policy.category, policy.id)
            if policy.kind == "app" and app and policy.value.lower() == app.lower():
                return Decision(False, f"allow rule #{policy.id}", policy.category, policy.id)

    # 2) device level restrictions (whole device blocked / no internet)
    if device is not None:
        if device.is_quarantined:
            return Decision(True, "device quarantined (no internet allowed)", "quarantine", device.id)
        if device.is_blocked:
            return Decision(True, "device is blocked", "device", device.id)

    # 3) explicit block rules
    categories = device_categories(device, default_categories)
    for policy in policies:
        if policy.action != "block" or not applies(policy):
            continue
        if policy.kind == "domain" and any(domain_matches(t, policy.value) for t in targets):
            return Decision(True, f"blocked by rule #{policy.id}", policy.category, policy.id)
        if policy.kind == "ip" and ip and _ip_match(ip, policy.value):
            return Decision(True, f"blocked by rule #{policy.id}", policy.category, policy.id)
        if policy.kind == "app" and app and policy.value.lower() == app.lower():
            return Decision(True, f"app blocked by rule #{policy.id}", policy.category, policy.id)
        if policy.kind == "category" and policy.category and policy.category in categories:
            return Decision(True, f"category blocked by rule #{policy.id}", policy.category, policy.id)

    # 4) global blocklist
    if targets:
        for entry in session.scalars(select(BlocklistEntry).where(BlocklistEntry.enabled.is_(True))).all():
            if any(domain_matches(t, entry.domain) for t in targets):
                return Decision(True, f"blocklist ({entry.category})", entry.category, entry.id)

    # 5) safe mode / curfew restrictions
    if device is not None:
        if device.is_safe_mode and categories & SAFE_MODE_CATEGORIES:
            hit = next(iter(categories & SAFE_MODE_CATEGORIES))
            return Decision(True, f"safe mode active (blocks {hit})", hit, None)
        for curfew in device.curfews:
            if not curfew.enabled:
                continue
            if not in_schedule(now, curfew.days, curfew.start_time, curfew.end_time):
                continue
            if curfew.action == "block_internet":
                return Decision(True, f"curfew '{curfew.label or curfew.id}' active", "curfew", curfew.id)
            if curfew.action == "safe_mode" and categories & SAFE_MODE_CATEGORIES:
                hit = next(iter(categories & SAFE_MODE_CATEGORIES))
                return Decision(True, f"curfew '{curfew.label or curfew.id}' active", hit, curfew.id)

    return Decision(False, "allowed")


def find_device_by_ip(session: Session, ip: str | None) -> Device | None:
    if not ip:
        return None
    return session.scalars(select(Device).where(Device.ip == ip)).first()


def _ip_match(ip: str, pattern: str) -> bool:
    import ipaddress

    try:
        if "/" in pattern:
            return ipaddress.ip_address(ip) in ipaddress.ip_network(pattern, strict=False)
        return ip == pattern
    except ValueError:
        return False
