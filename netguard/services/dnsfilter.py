"""NetGuard DNS filter: a small recursive DNS proxy that blocks domains.

Point a device's DNS at the machine running NetGuard and every lookup is
checked against the blocklist, the per-device rules, safe mode and curfews.
Blocked names resolve to 0.0.0.0 (A) / :: (AAAA), everything else is forwarded
to the upstream resolver (the ISP DNS by default).

Supports UDP and TCP (the TCP path is required for large answers).
"""
from __future__ import annotations

import socket
import struct
import threading
import time
from dataclasses import dataclass, field
from typing import Any

from sqlalchemy.orm import Session, sessionmaker

from ..db import BlockEvent, Device
from .policy import evaluate, find_device_by_ip

TYPE_A = 1
TYPE_AAAA = 28
CLASS_IN = 1


@dataclass
class DnsStats:
    started_at: float = field(default_factory=time.time)
    queries: int = 0
    blocked: int = 0
    forwarded: int = 0
    errors: int = 0
    recent: list[dict[str, Any]] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {
            "running": True,
            "uptime_seconds": round(time.time() - self.started_at),
            "queries": self.queries,
            "blocked": self.blocked,
            "forwarded": self.forwarded,
            "errors": self.errors,
            "recent": self.recent[-50:],
        }


class DnsFilterServer:
    """A tiny DNS proxy that applies the NetGuard policy engine."""

    def __init__(
        self,
        host: str = "0.0.0.0",
        port: int = 53,
        upstream: list[str] | None = None,
        session_factory: Any = None,
        default_categories: set[str] | None = None,
        log_blocks: bool = True,
    ):
        self.host = host
        self.port = port
        self.upstream = upstream or ["1.1.1.1", "8.8.8.8", "75.153.171.67"]
        self.session_factory = session_factory
        self.default_categories = default_categories or {"adult"}
        self.log_blocks = log_blocks
        self.stats = DnsStats()
        self._threads: list[threading.Thread] = []
        self._stop = threading.Event()
        self._udp: socket.socket | None = None
        self._tcp: socket.socket | None = None
        self.error: str | None = None

    # ------------------------------------------------------------- control
    def start(self) -> None:
        if self._threads:
            return
        self._stop.clear()
        try:
            self._udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self._udp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self._udp.bind((self.host, self.port))
        except OSError as exc:
            self.error = f"cannot bind UDP {self.host}:{self.port} ({exc})"
            self._udp = None
            return
        try:
            self._tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._tcp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self._tcp.bind((self.host, self.port))
            self._tcp.listen(64)
        except OSError as exc:
            self.error = f"cannot bind TCP {self.host}:{self.port} ({exc})"
            self._tcp = None

        self._threads.append(threading.Thread(target=self._udp_loop, daemon=True))
        if self._tcp:
            self._threads.append(threading.Thread(target=self._tcp_loop, daemon=True))
        for thread in self._threads:
            thread.start()

    def stop(self) -> None:
        self._stop.set()
        for sock in (self._udp, self._tcp):
            try:
                if sock:
                    sock.close()
            except OSError:
                pass
        self._udp = self._tcp = None
        self._threads = []

    # --------------------------------------------------------------- loops
    def _udp_loop(self) -> None:
        assert self._udp is not None
        while not self._stop.is_set():
            try:
                data, addr = self._udp.recvfrom(4096)
            except OSError:
                break
            try:
                reply = self.handle_query(data, addr[0])
                if reply:
                    self._udp.sendto(reply, addr)
            except Exception:
                self.stats.errors += 1

    def _tcp_loop(self) -> None:
        assert self._tcp is not None
        while not self._stop.is_set():
            try:
                conn, addr = self._tcp.accept()
            except OSError:
                break
            threading.Thread(target=self._tcp_client, args=(conn, addr), daemon=True).start()

    def _tcp_client(self, conn: socket.socket, addr) -> None:
        try:
            header = conn.recv(2)
            if len(header) < 2:
                return
            length = struct.unpack("!H", header)[0]
            data = b""
            while len(data) < length:
                chunk = conn.recv(length - len(data))
                if not chunk:
                    return
                data += chunk
            reply = self.handle_query(data, addr[0])
            if reply:
                conn.sendall(struct.pack("!H", len(reply)) + reply)
        except OSError:
            pass
        finally:
            try:
                conn.close()
            except OSError:
                pass

    # ------------------------------------------------------------- handling
    def handle_query(self, data: bytes, client_ip: str) -> bytes | None:
        self.stats.queries += 1
        parsed = parse_query(data)
        if not parsed:
            self.stats.errors += 1
            return None
        query_id, qname, qtype, question = parsed
        name = qname.lower().rstrip(".")

        blocked, reason, category = self._check(name, client_ip)
        if blocked:
            self.stats.blocked += 1
            self.stats.recent.insert(
                0,
                {
                    "ts": time.strftime("%Y-%m-%d %H:%M:%S"),
                    "client": client_ip,
                    "domain": name,
                    "reason": reason,
                    "category": category,
                },
            )
            del self.stats.recent[50:]
            return build_blocked_response(query_id, question, qtype)
        self.stats.forwarded += 1
        return self._forward(data, query_id)

    def _check(self, name: str, client_ip: str) -> tuple[bool, str, str | None]:
        if self.session_factory is None:
            return False, "", None
        session: Session = self.session_factory()
        try:
            device = find_device_by_ip(session, client_ip)
            decision = evaluate(
                session,
                device,
                domain=name,
                default_categories=self.default_categories,
            )
            if decision.blocked:
                if self.log_blocks:
                    session.add(
                        BlockEvent(
                            device_id=device.id if device else None,
                            target=name,
                            kind="domain",
                            category=decision.category,
                            reason=decision.reason,
                        )
                    )
                    session.commit()
                return True, decision.reason, decision.category
            return False, decision.reason, decision.category
        finally:
            session.close()

    def _forward(self, data: bytes, query_id: int) -> bytes | None:
        for server in self.upstream:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                    sock.settimeout(4)
                    sock.sendto(data, (server, 53))
                    reply, _ = sock.recvfrom(4096)
                # keep the original transaction id
                return reply[:2] + struct.pack("!H", query_id) + reply[4:]
            except OSError:
                continue
        self.stats.errors += 1
        return build_servfail(query_id)


# ------------------------------------------------------------------ helpers
def parse_query(data: bytes) -> tuple[int, str, int, bytes] | None:
    """Return (id, qname, qtype, question-section bytes)."""
    if len(data) < 12:
        return None
    query_id, flags, qdcount = struct.unpack("!HHH", data[:6])
    if flags & 0x8000:  # already a response
        return None
    offset = 12
    labels: list[str] = []
    question_start = offset
    try:
        while offset < len(data):
            length = data[offset]
            offset += 1
            if length == 0:
                break
            if length & 0xC0:
                return None
            labels.append(data[offset : offset + length].decode("ascii", errors="ignore"))
            offset += length
        if offset + 4 > len(data):
            return None
        qtype, _qclass = struct.unpack("!HH", data[offset : offset + 4])
        offset += 4
    except (UnicodeError, struct.error):
        return None
    if qdcount < 1:
        return None
    return query_id, ".".join(labels), qtype, data[question_start:offset]


def build_blocked_response(query_id: int, question: bytes, qtype: int) -> bytes:
    """Build a response that resolves the name to 0.0.0.0 / ::."""
    flags = 0x8180  # QR + RD + RA, RCODE 0
    header = struct.pack("!HHHHHH", query_id, flags, 1, 1, 0, 0)
    if qtype == TYPE_AAAA:
        rdata = b"\x00" * 16
        answer = struct.pack("!HHHIH", 0xC00C, TYPE_AAAA, CLASS_IN, 60, len(rdata)) + rdata
    else:
        rdata = b"\x00\x00\x00\x00"
        answer = struct.pack("!HHHIH", 0xC00C, TYPE_A, CLASS_IN, 60, len(rdata)) + rdata
    return header + question + answer


def build_servfail(query_id: int) -> bytes:
    return struct.pack("!HHHHHH", query_id, 0x8182, 0, 0, 0, 0)
