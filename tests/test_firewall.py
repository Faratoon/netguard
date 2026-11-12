"""Tests for the router command generation (dnsmasq + iptables)."""
from netguard.services.firewall import (
    build_device_block_commands,
    build_dnsmasq_commands,
    build_quarantine_commands,
)


def test_dnsmasq_commands_contain_blocked_domains():
    commands = build_dnsmasq_commands(["example.com", "bad.test"], "/tmp/ng/hosts")
    joined = "\n".join(commands)
    assert "address=/example.com/0.0.0.0" in joined
    assert "address=/bad.test/0.0.0.0" in joined
    assert "/tmp/ng/hosts" in joined
    assert "dnsmasq reload" in joined


def test_device_block_commands_use_mac():
    commands = build_device_block_commands(["aa:bb:cc:dd:ee:ff"], [])
    assert any("--mac-source AA:BB:CC:DD:EE:FF" in cmd for cmd in commands)


def test_quarantine_uses_reject():
    commands = build_quarantine_commands(["aa:bb:cc:dd:ee:ff"])
    assert any("-j REJECT" in cmd for cmd in commands)
