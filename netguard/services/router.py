"""Router abstraction: talk to OpenWrt / generic SSH routers, or a mock for demos."""
from __future__ import annotations

import re
import shutil
import subprocess
from dataclasses import dataclass, field
from typing import Any

from ..config import RouterConfig


class RouterError(RuntimeError):
    pass


@dataclass
class RouterDevice:
    mac: str
    ip: str | None = None
    hostname: str | None = None
    interface: str | None = None
    signal_dbm: float | None = None
    rx_bytes: int = 0
    tx_bytes: int = 0


@dataclass
class RouterStatus:
    model: str = "unknown"
    firmware: str = "unknown"
    hostname: str = "router"
    uptime_seconds: int = 0
    load_avg: list[float] = field(default_factory=list)
    cpu_percent: float | None = None
    mem_percent: float | None = None
    mem_total_kb: int | None = None
    mem_available_kb: int | None = None
    wan_ip: str | None = None
    wan_gateway: str | None = None
    dns_servers: list[str] = field(default_factory=list)
    lan_ip: str | None = None
    dhcp_pool: str | None = None
    wireless: list[dict[str, Any]] = field(default_factory=list)
    raw: dict[str, Any] = field(default_factory=dict)


class BaseRouter:
    def __init__(self, cfg: RouterConfig):
        self.cfg = cfg

    # -- capabilities ---------------------------------------------------
    def exec(self, command: str, timeout: int | None = None) -> str:
        raise NotImplementedError

    def status(self) -> RouterStatus:
        raise NotImplementedError

    def clients(self) -> list[RouterDevice]:
        raise NotImplementedError

    def reachable(self) -> bool:
        try:
            self.exec("true", timeout=5)
            return True
        except Exception:
            return False


class SSHRouter(BaseRouter):
    """Talks to a router over SSH using the system `ssh` client."""

    def _base_cmd(self) -> list[str]:
        cmd = [
            "ssh",
            "-o",
            "StrictHostKeyChecking=no",
            "-o",
            "UserKnownHostsFile=~/.ssh/known_hosts",
            "-o",
            "BatchMode=yes",
            "-o",
            f"ConnectTimeout={self.cfg.timeout}",
            "-p",
            str(self.cfg.port),
        ]
        if self.cfg.key_file:
            cmd += ["-i", self.cfg.key_file]
        cmd += [f"{self.cfg.user}@{self.cfg.host}"]
        return cmd

    def exec(self, command: str, timeout: int | None = None) -> str:
        timeout = timeout or self.cfg.timeout
        full: list[str]
        if self.cfg.password:
            if not shutil.which("sshpass"):
                raise RouterError("sshpass is not installed but a router password is configured")
            full = ["sshpass", "-p", self.cfg.password] + self._base_cmd() + [command]
        else:
            full = self._base_cmd() + [command]
        proc = subprocess.run(full, capture_output=True, text=True, timeout=timeout + 5)
        if proc.returncode != 0:
            raise RouterError(f"ssh command failed ({proc.returncode}): {proc.stderr.strip()[:400]}")
        return proc.stdout

    # -- data collectors ------------------------------------------------
    def status(self) -> RouterStatus:
        st = RouterStatus(raw={})
        board = self._json("ubus call system board") or {}
        st.raw["board"] = board
        st.model = board.get("model") or board.get("system") or "unknown"
        st.firmware = board.get("release", {}).get("description") or board.get("kernel") or "unknown"
        st.hostname = board.get("hostname", "router")

        loadavg = self.exec("cat /proc/loadavg 2>/dev/null || true").strip()
        if loadavg:
            parts = loadavg.split()
            st.load_avg = [float(p) for p in parts[:3] if _is_float(p)]
        meminfo = self.exec("cat /proc/meminfo 2>/dev/null || true")
        st.mem_total_kb = _mem_kb(meminfo, "MemTotal")
        st.mem_available_kb = _mem_kb(meminfo, "MemAvailable")
        if st.mem_total_kb and st.mem_available_kb:
            st.mem_percent = round((1 - st.mem_available_kb / st.mem_total_kb) * 100, 1)

        uptime_raw = self.exec("cat /proc/uptime 2>/dev/null || true").strip().split()
        if uptime_raw:
            try:
                st.uptime_seconds = int(float(uptime_raw[0]))
            except ValueError:
                pass

        wan = self._json(f"ubus call network.interface.{self.cfg.wan_interface} status") or {}
        st.raw["wan"] = wan
        wan_ubus = wan.get("ipv4-address", [{}])
        st.wan_ip = wan_ubus[0].get("address") if wan_ubus else None
        st.wan_gateway = wan.get("gateway")
        dns = []
        for ns in wan.get("dns-server", []) or []:
            dns.append(ns.get("address", ""))
        st.dns_servers = [d for d in dns if d]

        lan = self._json(f"ubus call network.interface.{self.cfg.lan_interface} status") or {}
        st.raw["lan"] = lan
        lan_ubus = lan.get("ipv4-address", [{}])
        st.lan_ip = lan_ubus[0].get("address") if lan_ubus else None

        dhcp = self.exec("uci show dhcp 2>/dev/null | grep -E 'start|limit|range' || true")
        st.dhcp_pool = dhcp.strip() or None

        wifi = []
        for ssid_info in self._json("ubus call wireless status") or []:
            wifi.append(
                {
                    "radio": ssid_info.get("radio"),
                    "ssid": ssid_info.get("config", {}).get("ssid"),
                    "up": ssid_info.get("up"),
                }
            )
        st.wireless = wifi
        st.raw["traffic"] = self.exec("cat /proc/net/dev 2>/dev/null || true")
        return st

    def clients(self) -> list[RouterDevice]:
        devices: dict[str, RouterDevice] = {}
        for line in self.exec("cat /tmp/dhcp.leases 2>/dev/null || true").splitlines():
            parts = line.split()
            if len(parts) < 4:
                continue
            expiry, mac, ip, hostname = parts[0], parts[1], parts[2], parts[3]
            devices[mac.upper()] = RouterDevice(mac=mac.upper(), ip=ip, hostname=hostname, interface="lease")

        for line in self.exec("cat /proc/net/arp 2>/dev/null || true").splitlines()[1:]:
            parts = line.split()
            if len(parts) < 6 or parts[3] != "0x2":
                continue
            ip, _flag, mac, _dev = parts[0], parts[1], parts[2], parts[3]
            mac = mac.upper()
            if mac in devices:
                devices[mac].ip = ip
            else:
                devices[mac] = RouterDevice(mac=mac, ip=ip, interface="arp")

        counters = self._parse_net_dev(self.exec("cat /proc/net/dev 2>/dev/null || true"))
        for mac, dev in devices.items():
            if mac in counters:
                dev.rx_bytes, dev.tx_bytes = counters[mac]
        return list(devices.values())

    def _parse_net_dev(self, text: str) -> dict[str, tuple[int, int]]:
        out: dict[str, tuple[int, int]] = {}
        for line in text.splitlines():
            if ":" not in line:
                continue
            name, _, rest = line.partition(":")
            parts = rest.split()
            if len(parts) < 9:
                continue
            try:
                rx, tx = int(parts[0]), int(parts[8])
            except ValueError:
                continue
            out[name.strip()] = (rx, tx)
        return out

    def _json(self, command: str) -> Any:
        import json

        try:
            raw = self.exec(command)
        except RouterError:
            return None
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            return None


class MockRouter(BaseRouter):
    """In-memory fake router used by demo mode and the test-suite."""

    def __init__(self, cfg: RouterConfig):
        super().__init__(cfg)
        self._clients = [
            RouterDevice("AA:BB:CC:00:00:01", "192.168.1.50", "kids-phone", signal_dbm=-52, rx_bytes=1_200_000_000, tx_bytes=340_000_000),
            RouterDevice("AA:BB:CC:00:00:02", "192.168.1.51", "dad-phone", signal_dbm=-41, rx_bytes=4_500_000_000, tx_bytes=1_100_000_000),
            RouterDevice("AA:BB:CC:00:00:03", "192.168.1.52", "living-room-tv", signal_dbm=-60, rx_bytes=8_900_000_000, tx_bytes=120_000_000),
            RouterDevice("AA:BB:CC:00:00:04", "192.168.1.53", "laptop-maryam", signal_dbm=-38, rx_bytes=2_100_000_000, tx_bytes=700_000_000),
            RouterDevice("AA:BB:CC:00:00:05", "192.168.1.54", "smart-tv", signal_dbm=-66),
        ]
        self.applied: list[str] = []

    def exec(self, command: str, timeout: int | None = None) -> str:
        self.applied.append(command)
        if command.startswith("cat /tmp/dhcp.leases"):
            now = int(__import__("time").time())
            return "\n".join(
                f"{now} {d.mac} {d.ip} {d.hostname} *" for d in self._clients if d.ip
            )
        if command.startswith("cat /proc/net/arp"):
            return "IP address       HW type     Flags       HW address            Mask     Device\n" + "\n".join(
                f"{d.ip}     0x1         0x2         {d.mac}     *     br-lan" for d in self._clients if d.ip
            )
        if command.startswith("cat /proc/loadavg"):
            return "0.42 0.31 0.25 2/118 4521"
        if command.startswith("cat /proc/meminfo"):
            return "MemTotal:        256000 kB\nMemAvailable:     128000 kB"
        if command.startswith("cat /proc/uptime"):
            return "864000.42 3200000.11"
        return ""

    def status(self) -> RouterStatus:
        return RouterStatus(
            model="Mock Router (demo)",
            firmware="NetGuard demo 1.0",
            hostname="demo-router",
            uptime_seconds=864000,
            load_avg=[0.42, 0.31, 0.25],
            cpu_percent=12.5,
            mem_percent=50.0,
            mem_total_kb=256000,
            mem_available_kb=128000,
            wan_ip="203.0.113.10",
            wan_gateway="203.0.113.1",
            dns_servers=["1.1.1.1", "8.8.8.8"],
            lan_ip="192.168.1.1",
            dhcp_pool="192.168.1.100-192.168.1.249",
            wireless=[{"radio": "radio0", "ssid": "HomeWiFi", "up": True}],
            raw={"note": "mock router - no real hardware touched"},
        )

    def clients(self) -> list[RouterDevice]:
        return list(self._clients)


def build_router(cfg: RouterConfig) -> BaseRouter:
    vendor = (cfg.vendor or "openwrt").lower()
    if vendor in {"mock", "demo"}:
        return MockRouter(cfg)
    if vendor in {"openwrt", "generic-ssh", "ssh", "lede"}:
        return SSHRouter(cfg)
    raise RouterError(f"unsupported router vendor: {cfg.vendor}")


def _is_float(value: str) -> bool:
    return bool(re.match(r"^\d+(\.\d+)?$", value))
