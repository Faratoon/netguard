"""Translate NetGuard policies into router commands and push them (or preview them)."""
from __future__ import annotations

from dataclasses import dataclass, field

from .router import BaseRouter, RouterError


@dataclass
class ApplyResult:
    dry_run: bool
    commands: list[str] = field(default_factory=list)
    applied: bool = False
    error: str | None = None


def build_dnsmasq_commands(domains: list[str], hosts_file: str) -> list[str]:
    """Create a dnsmasq include file that blackholes the given domains."""
    lines = [f"address=/{d}/0.0.0.0" for d in sorted(set(domains))]
    body = "\n".join(lines) + "\n"
    heredoc = (
        f"mkdir -p $(dirname {hosts_file}) && "
        f"cat > {hosts_file} <<'NETGUARD_EOF'\n{body}NETGUARD_EOF"
    )
    return [
        heredoc,
        # make sure dnsmasq actually reads the include file
        f"uci -q get dhcp.@dnsmasq[0].addnhosts || uci add_list dhcp.@dnsmasq[0].addnhosts='{hosts_file}'",
        "uci -q delete dhcp.@dnsmasq[0].addnhosts 2>/dev/null || true",
        f"uci add_list dhcp.@dnsmasq[0].addnhosts='{hosts_file}'",
        "/etc/init.d/dnsmasq reload",
    ]


def build_device_block_commands(macs: list[str], ips: list[str], comment: str = "netguard") -> list[str]:
    cmds: list[str] = []
    for mac in macs:
        mac = mac.upper()
        cmds.append(
            f"iptables -C FORWARD -m mac --mac-source {mac} -m comment --comment {comment} -j DROP "
            f"2>/dev/null || iptables -I FORWARD -m mac --mac-source {mac} -m comment --comment {comment} -j DROP"
        )
    for ip in ips:
        cmds.append(
            f"iptables -C FORWARD -s {ip} -m comment --comment {comment} -j DROP "
            f"2>/dev/null || iptables -I FORWARD -s {ip} -m comment --comment {comment} -j DROP"
        )
    return cmds


def build_allow_commands(macs: list[str], comment: str = "netguard-allow") -> list[str]:
    return [
        f"iptables -D FORWARD -m mac --mac-source {m.upper()} -m comment --comment {comment} -j DROP 2>/dev/null || true"
        for m in macs
    ]


def build_quarantine_commands(macs: list[str], comment: str = "netguard-quarantine") -> list[str]:
    return [
        f"iptables -C FORWARD -m mac --mac-source {m.upper()} -m comment --comment {comment} -j REJECT "
        f"2>/dev/null || iptables -I FORWARD -m mac --mac-source {m.upper()} -m comment --comment {comment} -j REJECT"
        for m in macs
    ]


def apply_commands(router: BaseRouter, commands: list[str], dry_run: bool = True) -> ApplyResult:
    if dry_run:
        return ApplyResult(dry_run=True, commands=list(commands), applied=False)
    errors: list[str] = []
    for cmd in commands:
        try:
            router.exec(cmd)
        except RouterError as exc:
            errors.append(str(exc))
    return ApplyResult(
        dry_run=False,
        commands=list(commands),
        applied=not errors,
        error="; ".join(errors) if errors else None,
    )
