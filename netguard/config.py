"""Configuration loading (YAML file + environment overrides)."""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

DEFAULT_CONFIG_PATH = Path(
    os.environ.get("NETGUARD_CONFIG", Path(__file__).resolve().parent.parent / "config.yaml")
)


@dataclass
class RouterConfig:
    """How to reach the router we manage."""

    vendor: str = "openwrt"  # openwrt | generic-ssh | mock
    host: str = "192.168.1.1"
    port: int = 22
    user: str = "root"
    password: str | None = None
    key_file: str | None = None
    wan_interface: str = "wan"
    lan_interface: str = "lan"
    dnsmasq_hosts_file: str = "/tmp/netguard/hosts.d/netguard-blocked"
    dry_run: bool = True  # True = never push rules to the router, just log them
    timeout: int = 15


@dataclass
class FilteringConfig:
    """DNS / content filtering behaviour."""

    enabled: bool = True
    default_block_categories: list[str] = field(default_factory=lambda: ["adult"])
    allowlist_domains: list[str] = field(default_factory=list)
    blocklist_file: str | None = None  # optional local domain list to import


@dataclass
class StorageConfig:
    data_dir: str = "./data"
    database_url: str | None = None
    max_upload_mb: int = 10


@dataclass
class MonitoringConfig:
    sample_interval_seconds: int = 60
    retention_days: int = 30
    speedtest_enabled: bool = True
    speedtest_timeout: int = 30
    default_ping_target: str = "1.1.1.1"


@dataclass
class AppConfig:
    router: RouterConfig = field(default_factory=RouterConfig)
    filtering: FilteringConfig = field(default_factory=FilteringConfig)
    storage: StorageConfig = field(default_factory=StorageConfig)
    monitoring: MonitoringConfig = field(default_factory=MonitoringConfig)
    host: str = "0.0.0.0"
    port: int = 8080
    api_token: str | None = None
    demo_mode: bool = False

    @property
    def data_path(self) -> Path:
        p = Path(self.storage.data_dir).expanduser().resolve()
        p.mkdir(parents=True, exist_ok=True)
        (p / "media").mkdir(exist_ok=True)
        return p

    @property
    def media_path(self) -> Path:
        return self.data_path / "media"

    @property
    def sqlalchemy_url(self) -> str:
        if self.storage.database_url:
            return self.storage.database_url
        return f"sqlite:///{self.data_path / 'netguard.db'}"


def _merge(base: dict[str, Any], extra: dict[str, Any]) -> dict[str, Any]:
    out = dict(base)
    for key, value in (extra or {}).items():
        if isinstance(value, dict) and isinstance(out.get(key), dict):
            out[key] = _merge(out[key], value)
        else:
            out[key] = value
    return out


def _build(cls, data: dict[str, Any]):
    fields = {f for f in cls.__dataclass_fields__}
    return cls(**{k: v for k, v in (data or {}).items() if k in fields})


def load_config(path: str | Path | None = None) -> AppConfig:
    cfg_path = Path(path) if path else DEFAULT_CONFIG_PATH
    raw: dict[str, Any] = {}
    if cfg_path.exists():
        raw = yaml.safe_load(cfg_path.read_text()) or {}
    raw = _merge(raw, _env_overrides())

    app = _build(AppConfig, raw)
    app.router = _build(RouterConfig, raw.get("router"))
    app.filtering = _build(FilteringConfig, raw.get("filtering"))
    app.storage = _build(StorageConfig, raw.get("storage"))
    app.monitoring = _build(MonitoringConfig, raw.get("monitoring"))
    return app


def _env_overrides() -> dict[str, Any]:
    env = os.environ
    out: dict[str, Any] = {}
    if env.get("NETGUARD_ROUTER_HOST"):
        out.setdefault("router", {})["host"] = env["NETGUARD_ROUTER_HOST"]
    if env.get("NETGUARD_ROUTER_USER"):
        out.setdefault("router", {})["user"] = env["NETGUARD_ROUTER_USER"]
    if env.get("NETGUARD_ROUTER_PASSWORD"):
        out.setdefault("router", {})["password"] = env["NETGUARD_ROUTER_PASSWORD"]
    if env.get("NETGUARD_ROUTER_KEY"):
        out.setdefault("router", {})["key_file"] = env["NETGUARD_ROUTER_KEY"]
    if env.get("NETGUARD_ROUTER_VENDOR"):
        out.setdefault("router", {})["vendor"] = env["NETGUARD_ROUTER_VENDOR"]
    if env.get("NETGUARD_DRY_RUN") is not None:
        out.setdefault("router", {})["dry_run"] = env["NETGUARD_DRY_RUN"].lower() in {"1", "true", "yes"}
    if env.get("NETGUARD_API_TOKEN"):
        out["api_token"] = env["NETGUARD_API_TOKEN"]
    if env.get("NETGUARD_DATA_DIR"):
        out.setdefault("storage", {})["data_dir"] = env["NETGUARD_DATA_DIR"]
    if env.get("NETGUARD_DEMO") is not None:
        out["demo_mode"] = env["NETGUARD_DEMO"].lower() in {"1", "true", "yes"}
    return out
