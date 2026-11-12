"""Policy evaluation shared by the REST API and the DNS filter server."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..db import BlocklistEntry, CategoryDomain, Curfew, Device, Policy
from .lists import SAFE_MODE_CATEGORIES
from .rules import MIC_SENSITIVE_APPS, Decision, domain_matches, in_schedule, normalize_domain

__all__ = [
    "SAFE_MODE_CATEGORIES",
    "evaluate",
    "device_categories",
    "find_device_by_ip",
    "category_of_domain",
]


def device_categories(device: Device | None, default_categories: set[str] | None = None) -> set[str]:
    """Categories that are blocked for this device."""
    cats = set(default_categories or {"adult"})
    if device is not None and device.is_safe_mode:
        cats |= SAFE_MODE_CATEGORIES
    return cats


def category_of_domain(session: Session, domain: str) -> str | None:
    """Return the category a domain belongs to (adult / social / gaming / risky)."""
    if not domain:
        return None
    domain = normalize_domain(domain)
    entry = session.scalars(
        select(CategoryDomain).where(CategoryDomain.domain == domain)
    ).first()
    if entry:
        return entry.category
    # fall back to a wildcard match ("*.example.com")
    for candidate in session.scalars(select(CategoryDomain)).all():
        if domain_matches(domain, candidate.domain):
            return candidate.category
    return None


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

    # 4) global blocklist - applies to every device
    if targets:
        for entry in session.scalars(select(BlocklistEntry).where(BlocklistEntry.enabled.is_(True))).all():
            if any(domain_matches(t, entry.domain) for t in targets):
                return Decision(True, f"blocklist ({entry.category})", entry.category, entry.id)

    # 5) category lists - only for devices that have the category switched on
    #    (safe mode, an explicit category rule or a curfew in safe mode)
    blocked_categories = set(categories)
    for curfew in device.curfews if device is not None else []:
        if not curfew.enabled:
            continue
        if curfew.action != "safe_mode":
            continue
        if in_schedule(now, curfew.days, curfew.start_time, curfew.end_time):
            blocked_categories |= SAFE_MODE_CATEGORIES

    explicit_categories = {
        policy.category
        for policy in policies
        if policy.action == "block" and policy.kind == "category" and applies(policy) and policy.category
    }
    blocked_categories |= explicit_categories

    if targets and blocked_categories:
        for target in targets:
            category = category_of_domain(session, target)
            if category and category in blocked_categories:
                return Decision(True, f"category '{category}' is blocked for this device", category, None)

    # 6) curfews that cut the internet completely
    if device is not None:
        for curfew in device.curfews:
            if not curfew.enabled:
                continue
            if curfew.action != "block_internet":
                continue
            if in_schedule(now, curfew.days, curfew.start_time, curfew.end_time):
                return Decision(True, f"curfew '{curfew.label or curfew.id}' active", "curfew", curfew.id)

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
