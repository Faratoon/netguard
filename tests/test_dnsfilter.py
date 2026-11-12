"""Tests for the DNS filter server."""
import socket
import struct

import pytest
from sqlalchemy.orm import sessionmaker

from netguard.db import BlocklistEntry, init_engine
from netguard.services.dnsfilter import DnsFilterServer, parse_query


@pytest.fixture()
def dns_server(tmp_path):
    engine = init_engine(f"sqlite:///{tmp_path}/dns.db")
    Session = sessionmaker(bind=engine, expire_on_commit=False)
    with Session() as session:
        session.add(BlocklistEntry(domain="blocked.test", category="adult"))
        session.add(BlocklistEntry(domain="*.wild.test", category="adult"))
        session.commit()

    server = DnsFilterServer(host="127.0.0.1", port=0, upstream=["1.1.1.1"], session_factory=Session)
    server.start()
    yield server
    server.stop()


def _query(server, name, timeout=5):
    qid = 0x1234
    data = (
        struct.pack("!HHHHHH", qid, 0x0100, 1, 0, 0, 0)
        + b"".join(bytes([len(part)]) + part.encode() for part in name.split("."))
        + b"\x00"
        + struct.pack("!HH", 1, 1)
    )
    port = server._udp.getsockname()[1]
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.sendto(data, ("127.0.0.1", port))
        reply, _ = sock.recvfrom(4096)
    finally:
        sock.close()
    answers = struct.unpack("!H", reply[6:8])[0]
    return answers, reply[-4:] if answers else b""


def test_parse_query():
    data = (
        struct.pack("!HHHHHH", 1, 0x0100, 1, 0, 0, 0)
        + b"\x07blocked\x04test\x00"
        + struct.pack("!HH", 1, 1)
    )
    parsed = parse_query(data)
    assert parsed is not None
    assert parsed[1] == "blocked.test"
    assert parsed[2] == 1


def test_blocked_domain_resolves_to_zero(dns_server):
    answers, rdata = _query(dns_server, "blocked.test")
    assert answers == 1
    assert rdata == b"\x00\x00\x00\x00"


def test_wildcard_block(dns_server):
    answers, rdata = _query(dns_server, "sub.wild.test")
    assert answers == 1
    assert rdata == b"\x00\x00\x00\x00"


def test_stats_count_blocked(dns_server):
    _query(dns_server, "blocked.test")
    assert dns_server.stats.blocked >= 1
    assert dns_server.stats.recent[0]["domain"] == "blocked.test"
