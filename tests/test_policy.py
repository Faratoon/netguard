"""Tests for the category based filtering (safe mode / per-device categories)."""
import pytest

from netguard.db import BlocklistEntry, CategoryDomain, Device, init_engine
from netguard.services.policy import evaluate
from sqlalchemy.orm import sessionmaker


@pytest.fixture()
def session(tmp_path):
    engine = init_engine(f"sqlite:///{tmp_path}/policy.db")
    Session = sessionmaker(bind=engine, expire_on_commit=False)
    db = Session()
    db.add(CategoryDomain(domain="pornhub.com", category="adult"))
    db.add(CategoryDomain(domain="roblox.com", category="gaming"))
    db.add(CategoryDomain(domain="discord.com", category="social"))
    db.add(BlocklistEntry(domain="pornhub.com", category="adult"))
    db.commit()
    yield db
    db.close()


def test_adult_is_blocked_for_everyone(session):
    device = Device(mac="AA:BB:CC:00:00:01", ip="192.168.1.10")
    session.add(device)
    session.commit()
    decision = evaluate(session, device, domain="pornhub.com")
    assert decision.blocked is True


def test_gaming_is_allowed_without_safe_mode(session):
    device = Device(mac="AA:BB:CC:00:00:02", ip="192.168.1.11")
    session.add(device)
    session.commit()
    decision = evaluate(session, device, domain="roblox.com")
    assert decision.blocked is False


def test_gaming_is_blocked_with_safe_mode(session):
    device = Device(mac="AA:BB:CC:00:00:03", ip="192.168.1.12", is_safe_mode=True)
    session.add(device)
    session.commit()
    decision = evaluate(session, device, domain="roblox.com")
    assert decision.blocked is True
    assert decision.category == "gaming"


def test_safe_mode_does_not_block_unrelated_sites(session):
    device = Device(mac="AA:BB:CC:00:00:04", ip="192.168.1.13", is_safe_mode=True)
    session.add(device)
    session.commit()
    decision = evaluate(session, device, domain="wikipedia.org")
    assert decision.blocked is False


def test_explicit_category_rule_blocks_for_that_device(session):
    kid = Device(mac="AA:BB:CC:00:00:05", ip="192.168.1.14")
    grown_up = Device(mac="AA:BB:CC:00:00:06", ip="192.168.1.15")
    session.add_all([kid, grown_up])
    session.commit()
    from netguard.db import Policy

    session.add(Policy(device_id=kid.id, kind="category", value="gaming", category="gaming", action="block"))
    session.commit()
    assert evaluate(session, kid, domain="roblox.com").blocked is True
    assert evaluate(session, grown_up, domain="roblox.com").blocked is False
