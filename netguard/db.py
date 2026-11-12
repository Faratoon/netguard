"""Database engine, session factory and models."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Generator

from sqlalchemy import Boolean, DateTime, Float, ForeignKey, Integer, String, Text, create_engine
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, relationship, sessionmaker


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Base(DeclarativeBase):
    pass


class Device(Base):
    """A device seen on the local network (phone, laptop, TV, IoT...)."""

    __tablename__ = "devices"

    id: Mapped[int] = mapped_column(primary_key=True)
    mac: Mapped[str] = mapped_column(String(17), unique=True, index=True)
    ip: Mapped[str | None] = mapped_column(String(64), index=True)
    hostname: Mapped[str | None] = mapped_column(String(128))
    vendor: Mapped[str | None] = mapped_column(String(128))
    device_type: Mapped[str] = mapped_column(String(32), default="unknown")  # phone/tablet/pc/tv/iot
    friendly_name: Mapped[str | None] = mapped_column(String(128))
    notes: Mapped[str | None] = mapped_column(Text)
    photo_path: Mapped[str | None] = mapped_column(String(256))
    is_blocked: Mapped[bool] = mapped_column(Boolean, default=False)
    is_safe_mode: Mapped[bool] = mapped_column(Boolean, default=False)
    is_quarantined: Mapped[bool] = mapped_column(Boolean, default=False)  # no internet at all
    first_seen: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    last_seen: Mapped[datetime] = mapped_column(DateTime, default=utcnow)

    policies: Mapped[list["Policy"]] = relationship(back_populates="device", cascade="all, delete-orphan")
    curfews: Mapped[list["Curfew"]] = relationship(back_populates="device", cascade="all, delete-orphan")


class Policy(Base):
    """A rule applied to a device (or globally when device_id is NULL)."""

    __tablename__ = "policies"

    id: Mapped[int] = mapped_column(primary_key=True)
    device_id: Mapped[int | None] = mapped_column(ForeignKey("devices.id", ondelete="CASCADE"), index=True)
    kind: Mapped[str] = mapped_column(String(32))  # domain | ip | mac | app | category
    value: Mapped[str] = mapped_column(String(512))
    action: Mapped[str] = mapped_column(String(16), default="block")  # block | allow | limit
    category: Mapped[str | None] = mapped_column(String(64))
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    note: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)

    device: Mapped[Device | None] = relationship(back_populates="policies")


class BlocklistEntry(Base):
    """A domain (or domain pattern) that should be blocked."""

    __tablename__ = "blocklist"

    id: Mapped[int] = mapped_column(primary_key=True)
    domain: Mapped[str] = mapped_column(String(255), index=True)
    category: Mapped[str] = mapped_column(String(64), default="adult")
    source: Mapped[str] = mapped_column(String(64), default="manual")  # manual | import | preset
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    hits: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class CategoryDomain(Base):
    """A domain that belongs to a category (adult / social / gaming / risky).

    Adult domains are additionally stored in the global blocklist; the other
    categories are only blocked on devices that enable them (safe mode or an
    explicit category rule).
    """

    __tablename__ = "category_domains"

    id: Mapped[int] = mapped_column(primary_key=True)
    domain: Mapped[str] = mapped_column(String(255), index=True)
    category: Mapped[str] = mapped_column(String(64), default="adult", index=True)
    source: Mapped[str] = mapped_column(String(64), default="import")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class Curfew(Base):
    """Time based restriction for a device."""

    __tablename__ = "curfews"

    id: Mapped[int] = mapped_column(primary_key=True)
    device_id: Mapped[int] = mapped_column(ForeignKey("devices.id", ondelete="CASCADE"), index=True)
    label: Mapped[str | None] = mapped_column(String(128))
    days: Mapped[str] = mapped_column(String(64), default="0,1,2,3,4,5,6")  # 0=Monday
    start_time: Mapped[str] = mapped_column(String(5), default="21:00")
    end_time: Mapped[str] = mapped_column(String(5), default="07:00")
    action: Mapped[str] = mapped_column(String(32), default="safe_mode")  # block_internet | safe_mode
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)

    device: Mapped[Device | None] = relationship(back_populates="curfews")


class TrafficSample(Base):
    """One network traffic / load measurement."""

    __tablename__ = "traffic_samples"

    id: Mapped[int] = mapped_column(primary_key=True)
    ts: Mapped[datetime] = mapped_column(DateTime, default=utcnow, index=True)
    device_id: Mapped[int | None] = mapped_column(ForeignKey("devices.id", ondelete="SET NULL"), index=True)
    rx_bytes: Mapped[int] = mapped_column(Integer, default=0)
    tx_bytes: Mapped[int] = mapped_column(Integer, default=0)
    latency_ms: Mapped[float | None] = mapped_column(Float)
    cpu_percent: Mapped[float | None] = mapped_column(Float)
    mem_percent: Mapped[float | None] = mapped_column(Float)
    load_avg: Mapped[float | None] = mapped_column(Float)
    signal_dbm: Mapped[float | None] = mapped_column(Float)


class BlockEvent(Base):
    """Log of a blocked attempt (domain, app or IP)."""

    __tablename__ = "block_events"

    id: Mapped[int] = mapped_column(primary_key=True)
    ts: Mapped[datetime] = mapped_column(DateTime, default=utcnow, index=True)
    device_id: Mapped[int | None] = mapped_column(ForeignKey("devices.id", ondelete="SET NULL"))
    target: Mapped[str] = mapped_column(String(512))
    kind: Mapped[str] = mapped_column(String(32), default="domain")
    category: Mapped[str | None] = mapped_column(String(64))
    reason: Mapped[str | None] = mapped_column(String(255))
    image_path: Mapped[str | None] = mapped_column(String(256))  # optional screenshot


class ImageAsset(Base):
    """Any image managed by NetGuard (device photos, screenshots, topology maps)."""

    __tablename__ = "image_assets"

    id: Mapped[int] = mapped_column(primary_key=True)
    filename: Mapped[str] = mapped_column(String(256))
    kind: Mapped[str] = mapped_column(String(32), default="device_photo")  # device_photo | blocked_page | topology | router_admin
    title: Mapped[str | None] = mapped_column(String(255))
    related_id: Mapped[int | None] = mapped_column(Integer)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class RouterSnapshot(Base):
    """Raw router admin data captured periodically (board info, WAN status...)."""

    __tablename__ = "router_snapshots"

    id: Mapped[int] = mapped_column(primary_key=True)
    ts: Mapped[datetime] = mapped_column(DateTime, default=utcnow, index=True)
    payload: Mapped[str] = mapped_column(Text)


_engine = None
_Session = None


def init_engine(url: str):
    global _engine, _Session
    _engine = create_engine(url, future=True, connect_args={"check_same_thread": False} if url.startswith("sqlite") else {})
    _Session = sessionmaker(bind=_engine, expire_on_commit=False, future=True)
    Base.metadata.create_all(_engine)
    return _engine


def get_engine():
    if _engine is None:
        raise RuntimeError("engine not initialised")
    return _engine


def get_session() -> Generator[Session, None, None]:
    if _Session is None:
        raise RuntimeError("session factory not initialised")
    session = _Session()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()
