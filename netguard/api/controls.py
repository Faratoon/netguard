"""Parental controls: policies, curfews, blocklist, evaluation and rule deployment."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..db import BlockEvent, BlocklistEntry, Curfew, Device, Policy, get_session
from ..services import firewall
from ..services.rules import (
    CATEGORY_PRESETS,
    MIC_SENSITIVE_APPS,
    Decision,
    domain_matches,
    in_schedule,
    normalize_domain,
)
from ..state import STATE

router = APIRouter(prefix="/api/controls", tags=["controls"])

SAFE_MODE_CATEGORIES = {"adult", "social", "gaming", "risky"}


class PolicyIn(BaseModel):
    device_id: int | None = None
    kind: str = Field(default="domain", pattern="^(domain|ip|mac|app|category)$")
    value: str
    action: str = Field(default="block", pattern="^(block|allow|limit)$")
    category: str | None = None
    enabled: bool = True
    note: str | None = None


class CurfewIn(BaseModel):
    device_id: int
    label: str | None = None
    days: str = "0,1,2,3,4,5,6"
    start_time: str = "21:00"
    end_time: str = "07:00"
    action: str = Field(default="safe_mode", pattern="^(safe_mode|block_internet)$")
    enabled: bool = True


class BlocklistIn(BaseModel):
    domain: str
    category: str = "adult"
    source: str = "manual"
    enabled: bool = True


class BlocklistBulk(BaseModel):
    domains: list[str]
    category: str = "adult"
    source: str = "import"


class ApplyRequest(BaseModel):
    apply: bool = False  # True = actually push to the router, False = dry-run preview
    include_blocklist: bool = True
    include_device_blocks: bool = True


class CheckRequest(BaseModel):
    device_id: int | None = None
    domain: str | None = None
    ip: str | None = None
    app: str | None = None


# ------------------------------------------------------------------ policies
@router.get("/policies")
def list_policies(device_id: int | None = None, session: Session = Depends(get_session)) -> dict[str, Any]:
    stmt = select(Policy)
    if device_id is not None:
        stmt = stmt.where(Policy.device_id == device_id)
    rows = session.scalars(stmt.order_by(Policy.id.desc())).all()
    return {
        "policies": [
            {
                "id": p.id,
                "device_id": p.device_id,
                "kind": p.kind,
                "value": p.value,
                "action": p.action,
                "category": p.category,
                "enabled": p.enabled,
                "note": p.note,
            }
            for p in rows
        ]
    }


@router.post("/policies", status_code=201)
def create_policy(payload: PolicyIn, session: Session = Depends(get_session)) -> dict[str, Any]:
    if payload.device_id is not None and not session.get(Device, payload.device_id):
        raise HTTPException(status_code=404, detail="device not found")
    value = payload.value.strip()
    if payload.kind in {"domain", "ip"} and not value:
        raise HTTPException(status_code=422, detail="value must not be empty")
    policy = Policy(**payload.model_dump())
    session.add(policy)
    session.flush()
    return {"id": policy.id, "status": "created"}


@router.delete("/policies/{policy_id}")
def delete_policy(policy_id: int, session: Session = Depends(get_session)) -> dict[str, str]:
    policy = session.get(Policy, policy_id)
    if not policy:
        raise HTTPException(status_code=404, detail="policy not found")
    session.delete(policy)
    return {"status": "deleted"}


@router.patch("/policies/{policy_id}")
def toggle_policy(policy_id: int, enabled: bool, session: Session = Depends(get_session)) -> dict[str, Any]:
    policy = session.get(Policy, policy_id)
    if not policy:
        raise HTTPException(status_code=404, detail="policy not found")
    policy.enabled = enabled
    return {"id": policy.id, "enabled": enabled}


# ------------------------------------------------------------------ curfews
@router.get("/curfews")
def list_curfews(session: Session = Depends(get_session)) -> dict[str, Any]:
    rows = session.scalars(select(Curfew)).all()
    now = datetime.now(timezone.utc)
    return {
        "curfews": [
            {
                "id": c.id,
                "device_id": c.device_id,
                "device_name": c.device.friendly_name if c.device else None,
                "label": c.label,
                "days": c.days,
                "start_time": c.start_time,
                "end_time": c.end_time,
                "action": c.action,
                "enabled": c.enabled,
                "active_now": bool(c.enabled and in_schedule(now, c.days, c.start_time, c.end_time)),
            }
            for c in rows
        ]
    }


@router.post("/curfews", status_code=201)
def create_curfew(payload: CurfewIn, session: Session = Depends(get_session)) -> dict[str, Any]:
    if not session.get(Device, payload.device_id):
        raise HTTPException(status_code=404, detail="device not found")
    curfew = Curfew(**payload.model_dump())
    session.add(curfew)
    session.flush()
    return {"id": curfew.id, "status": "created"}


@router.delete("/curfews/{curfew_id}")
def delete_curfew(curfew_id: int, session: Session = Depends(get_session)) -> dict[str, str]:
    curfew = session.get(Curfew, curfew_id)
    if not curfew:
        raise HTTPException(status_code=404, detail="curfew not found")
    session.delete(curfew)
    return {"status": "deleted"}


# ----------------------------------------------------------------- blocklist
@router.get("/blocklist")
def list_blocklist(
    category: str | None = None, session: Session = Depends(get_session)
) -> dict[str, Any]:
    stmt = select(BlocklistEntry)
    if category:
        stmt = stmt.where(BlocklistEntry.category == category)
    rows = session.scalars(stmt.order_by(BlocklistEntry.id.desc())).all()
    return {
        "count": len(rows),
        "entries": [
            {
                "id": e.id,
                "domain": e.domain,
                "category": e.category,
                "source": e.source,
                "enabled": e.enabled,
                "hits": e.hits,
            }
            for e in rows
        ],
    }


@router.post("/blocklist", status_code=201)
def add_blocklist(payload: BlocklistIn, session: Session = Depends(get_session)) -> dict[str, Any]:
    domain = normalize_domain(payload.domain)
    if not domain:
        raise HTTPException(status_code=422, detail="invalid domain")
    existing = session.scalars(select(BlocklistEntry).where(BlocklistEntry.domain == domain)).first()
    if existing:
        existing.enabled = True
        existing.category = payload.category
        return {"id": existing.id, "status": "updated"}
    entry = BlocklistEntry(domain=domain, category=payload.category, source=payload.source)
    session.add(entry)
    session.flush()
    return {"id": entry.id, "status": "created"}


@router.post("/blocklist/bulk", status_code=201)
def add_blocklist_bulk(payload: BlocklistBulk, session: Session = Depends(get_session)) -> dict[str, Any]:
    added = 0
    for raw in payload.domains:
        domain = normalize_domain(raw)
        if not domain:
            continue
        existing = session.scalars(select(BlocklistEntry).where(BlocklistEntry.domain == domain)).first()
        if existing:
            continue
        session.add(BlocklistEntry(domain=domain, category=payload.category, source=payload.source))
        added += 1
    session.flush()
    return {"added": added}


@router.delete("/blocklist/{entry_id}")
def delete_blocklist(entry_id: int, session: Session = Depends(get_session)) -> dict[str, str]:
    entry = session.get(BlocklistEntry, entry_id)
    if not entry:
        raise HTTPException(status_code=404, detail="entry not found")
    session.delete(entry)
    return {"status": "deleted"}


@router.get("/presets")
def list_presets() -> dict[str, Any]:
    return {
        "categories": {name: domains for name, domains in CATEGORY_PRESETS.items()},
        "mic_sensitive_apps": MIC_SENSITIVE_APPS,
    }


@router.post("/presets/{category}/import")
def import_preset(category: str, session: Session = Depends(get_session)) -> dict[str, Any]:
    domains = CATEGORY_PRESETS.get(category)
    if domains is None:
        raise HTTPException(status_code=404, detail="unknown category")
    added = 0
    for domain in domains:
        existing = session.scalars(select(BlocklistEntry).where(BlocklistEntry.domain == domain)).first()
        if existing:
            continue
        session.add(BlocklistEntry(domain=domain, category=category, source="preset"))
        added += 1
    session.flush()
    return {"category": category, "added": added}


# ---------------------------------------------------------------- evaluation
def evaluate(
    session: Session,
    device: Device | None,
    domain: str | None = None,
    ip: str | None = None,
    app: str | None = None,
    now: datetime | None = None,
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

    # 2) explicit block rules
    for policy in policies:
        if policy.action != "block" or not applies(policy):
            continue
        if policy.kind == "domain" and any(domain_matches(t, policy.value) for t in targets):
            return Decision(True, f"blocked by rule #{policy.id}", policy.category, policy.id)
        if policy.kind == "ip" and ip and _ip_match(ip, policy.value):
            return Decision(True, f"blocked by rule #{policy.id}", policy.category, policy.id)
        if policy.kind == "app" and app and policy.value.lower() == app.lower():
            return Decision(True, f"app blocked by rule #{policy.id}", policy.category, policy.id)
        if policy.kind == "category" and policy.category in (device_categories(device) or set()):
            return Decision(True, f"category blocked by rule #{policy.id}", policy.category, policy.id)

    # 3) global blocklist
    if targets:
        for entry in session.scalars(select(BlocklistEntry).where(BlocklistEntry.enabled.is_(True))).all():
            if any(domain_matches(t, entry.domain) for t in targets):
                return Decision(True, f"blocklist ({entry.category})", entry.category, entry.id)

    # 4) safe mode / curfew restrictions
    if device is not None:
        categories = device_categories(device)
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


def device_categories(device: Device | None) -> set[str]:
    if device is None:
        return set()
    cats = set(STATE.config.filtering.default_block_categories)
    if device.is_safe_mode:
        cats |= SAFE_MODE_CATEGORIES
    return cats


def _ip_match(ip: str, pattern: str) -> bool:
    import ipaddress

    try:
        if "/" in pattern:
            return ipaddress.ip_address(ip) in ipaddress.ip_network(pattern, strict=False)
        return ip == pattern
    except ValueError:
        return False


@router.post("/check")
def check(payload: CheckRequest, session: Session = Depends(get_session)) -> dict[str, Any]:
    device = session.get(Device, payload.device_id) if payload.device_id else None
    decision = evaluate(session, device, payload.domain, payload.ip, payload.app)
    return {
        "blocked": decision.blocked,
        "reason": decision.reason,
        "category": decision.category,
        "rule_id": decision.rule_id,
    }


# --------------------------------------------------------------------- apply
@router.post("/apply")
def apply_rules(payload: ApplyRequest, session: Session = Depends(get_session)) -> dict[str, Any]:
    """Preview (dry-run) or push the current ruleset to the router."""
    router_client = STATE.router
    if router_client is None:
        raise HTTPException(status_code=503, detail="no router configured")

    commands: list[str] = []
    if payload.include_blocklist:
        domains = [
            e.domain
            for e in session.scalars(select(BlocklistEntry).where(BlocklistEntry.enabled.is_(True))).all()
        ]
        if domains:
            commands += firewall.build_dnsmasq_commands(domains, STATE.config.router.dnsmasq_hosts_file)

    if payload.include_device_blocks:
        blocked_macs = [d.mac for d in session.scalars(select(Device).where(Device.is_blocked.is_(True))).all()]
        quarantined = [d.mac for d in session.scalars(select(Device).where(Device.is_quarantined.is_(True))).all()]
        allowed = [d.mac for d in session.scalars(select(Device).where(Device.is_blocked.is_(False))).all()]
        if allowed:
            commands += firewall.build_allow_commands(allowed)
        if blocked_macs:
            commands += firewall.build_device_block_commands(blocked_macs, [])
        if quarantined:
            commands += firewall.build_quarantine_commands(quarantined)

    dry_run = not payload.apply or STATE.config.router.dry_run
    result = firewall.apply_commands(router_client, commands, dry_run=dry_run)
    return {
        "dry_run": result.dry_run,
        "applied": result.applied,
        "error": result.error,
        "commands": result.commands,
    }


@router.get("/events")
def list_events(limit: int = 100, session: Session = Depends(get_session)) -> dict[str, Any]:
    rows = session.scalars(select(BlockEvent).order_by(BlockEvent.ts.desc()).limit(limit)).all()
    return {
        "events": [
            {
                "id": e.id,
                "ts": e.ts.isoformat() if e.ts else None,
                "device_id": e.device_id,
                "target": e.target,
                "kind": e.kind,
                "category": e.category,
                "reason": e.reason,
                "image_path": e.image_path,
            }
            for e in rows
        ]
    }


@router.post("/events", status_code=201)
def log_event(payload: CheckRequest, session: Session = Depends(get_session)) -> dict[str, Any]:
    device = session.get(Device, payload.device_id) if payload.device_id else None
    decision = evaluate(session, device, payload.domain, payload.ip, payload.app)
    target = payload.domain or payload.ip or payload.app or "unknown"
    event = BlockEvent(
        device_id=payload.device_id,
        target=target,
        kind="ip" if payload.ip else ("app" if payload.app else "domain"),
        category=decision.category,
        reason=decision.reason,
    )
    session.add(event)
    session.flush()
    return {"id": event.id, "blocked": decision.blocked, "reason": decision.reason}
