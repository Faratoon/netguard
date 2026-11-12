"""Local network diagnostics: ping, traceroute, speed test, ARP table, port scan."""
from __future__ import annotations

import os
import platform
import shutil
import socket
import subprocess
import time
from dataclasses import dataclass, field

import httpx


@dataclass
class ToolResult:
    ok: bool
    output: str = ""
    detail: dict = field(default_factory=dict)


def ping(host: str, count: int = 4, timeout: int = 10) -> ToolResult:
    flag = "-n" if platform.system() == "Windows" else "-c"
    if not shutil.which("ping"):
        return ToolResult(False, "ping binary not available on this host")
    try:
        proc = subprocess.run(
            ["ping", flag, str(count), "-W", "2", host],
            capture_output=True,
            text=True,
            timeout=timeout + 5,
        )
    except subprocess.TimeoutExpired:
        return ToolResult(False, "ping timed out")
    out = (proc.stdout or "") + (proc.stderr or "")
    latency = _parse_ping_latency(out)
    return ToolResult(proc.returncode == 0, out.strip(), {"latency_ms": latency, "host": host})


def _parse_ping_latency(output: str) -> float | None:
    import re

    m = re.search(r"(?:rtt|round-trip)[^=]*=\s*([\d.]+)/([\d.]+)/([\d.]+)", output)
    if m:
        return float(m.group(3))
    m = re.search(r"time[=<]([\d.]+)\s*ms", output)
    if m:
        return float(m.group(1))
    return None


def traceroute(host: str, max_hops: int = 15, timeout: int = 40) -> ToolResult:
    if not shutil.which("traceroute"):
        return ToolResult(False, "traceroute not installed")
    try:
        proc = subprocess.run(
            ["traceroute", "-n", "-w", "2", "-m", str(max_hops), host],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        return ToolResult(False, "traceroute timed out")
    return ToolResult(proc.returncode == 0, (proc.stdout or proc.stderr).strip())


def dns_lookup(domain: str) -> ToolResult:
    try:
        infos = socket.getaddrinfo(domain, None)
    except socket.gaierror as exc:
        return ToolResult(False, str(exc))
    addrs = sorted({i[4][0] for i in infos})
    return ToolResult(True, "\n".join(addrs), {"addresses": addrs})


def speedtest(timeout: int = 30) -> ToolResult:
    """Measure download/upload speed.

    Uses ``speedtest-cli`` when installed, otherwise falls back to a plain
    HTTP download/upload probe against a public endpoint.
    """
    if shutil.which("speedtest-cli") or shutil.which("speedtest"):
        cmd = ["speedtest-cli", "--simple"] if shutil.which("speedtest-cli") else ["speedtest", "--accept-license", "--accept-gdpr"]
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 15)
            if proc.returncode == 0:
                return ToolResult(True, proc.stdout.strip(), _parse_speedtest(proc.stdout))
        except Exception:
            pass

    url = "https://speed.cloudflare.com/__down?bytes=10000000"
    try:
        start = time.time()
        with httpx.Client(timeout=timeout) as client:
            resp = client.get(url)
            payload = resp.content
        elapsed = max(time.time() - start, 0.001)
        mbps = (len(payload) * 8) / elapsed / 1_000_000
        return ToolResult(
            True,
            f"Download {mbps:.2f} Mbit/s ({len(payload) / 1_000_000:.1f} MB in {elapsed:.1f}s)",
            {"download_mbps": round(mbps, 2), "bytes": len(payload), "seconds": round(elapsed, 2)},
        )
    except Exception as exc:
        return ToolResult(False, f"speed test failed: {exc}")


def _parse_speedtest(text: str) -> dict:
    import re

    out: dict = {}
    m = re.search(r"Download:\s*([\d.]+)", text)
    if m:
        out["download_mbps"] = float(m.group(1))
    m = re.search(r"Upload:\s*([\d.]+)", text)
    if m:
        out["upload_mbps"] = float(m.group(1))
    m = re.search(r"Ping:\s*([\d.]+)", text)
    if m:
        out["latency_ms"] = float(m.group(1))
    return out


def local_arp_table() -> ToolResult:
    """Read the ARP table of the machine running NetGuard."""
    if platform.system() == "Linux":
        path = "/proc/net/arp"
        if os.path.exists(path):
            rows = []
            for line in open(path).read().splitlines()[1:]:
                parts = line.split()
                if len(parts) >= 6:
                    rows.append({"ip": parts[0], "mac": parts[3], "flags": parts[2], "device": parts[5]})
            return ToolResult(True, "\n".join(r["ip"] for r in rows), {"entries": rows})
    if platform.system() == "Windows":
        try:
            proc = subprocess.run(["arp", "-a"], capture_output=True, text=True, timeout=10)
            return ToolResult(proc.returncode == 0, proc.stdout.strip())
        except Exception as exc:
            return ToolResult(False, str(exc))
    if shutil.which("arp"):
        proc = subprocess.run(["arp", "-a"], capture_output=True, text=True, timeout=10)
        return ToolResult(proc.returncode == 0, proc.stdout.strip())
    return ToolResult(False, "no ARP source available on this platform")


def local_interfaces() -> ToolResult:
    """Read per-interface counters (rx/tx bytes) of the host machine."""
    if platform.system() == "Linux" and os.path.exists("/proc/net/dev"):
        rows = []
        for line in open("/proc/net/dev").read().splitlines()[2:]:
            name, _, rest = line.partition(":")
            parts = rest.split()
            if len(parts) >= 9:
                rows.append(
                    {
                        "interface": name.strip(),
                        "rx_bytes": int(parts[0]),
                        "tx_bytes": int(parts[8]),
                    }
                )
        return ToolResult(True, "", {"interfaces": rows})
    return ToolResult(False, "interface counters only available on Linux")


def scan_subnet(cidr: str = "192.168.1.0/24", timeout: float = 0.25) -> ToolResult:
    """Ping-sweep the local subnet and report live hosts."""
    import ipaddress

    try:
        network = ipaddress.ip_network(cidr, strict=False)
    except ValueError as exc:
        return ToolResult(False, str(exc))
    hosts = network.hosts()
    alive: list[dict] = []
    for host in hosts:
        ip = str(host)
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        try:
            if sock.connect_ex((ip, 80)) == 0:
                alive.append({"ip": ip, "open_ports": [80]})
        except OSError:
            pass
        finally:
            sock.close()
    return ToolResult(True, f"{len(alive)} host(s) reachable", {"hosts": alive})


def port_scan(host: str, ports: list[int] | None = None, timeout: float = 0.6) -> ToolResult:
    ports = ports or [22, 53, 80, 443, 445, 554, 8080, 8443]
    open_ports = []
    for port in ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        try:
            if sock.connect_ex((host, port)) == 0:
                open_ports.append(port)
        except OSError:
            pass
        finally:
            sock.close()
    return ToolResult(True, f"open ports: {open_ports or 'none'}", {"host": host, "open_ports": open_ports})


def traceroute_hops(host: str) -> ToolResult:
    return traceroute(host)
