"""Shared ASA parsing utilities."""

from __future__ import annotations

import ipaddress
import re


def mask_to_cidr(mask: str) -> int:
    try:
        return ipaddress.IPv4Network(f"0.0.0.0/{mask}", strict=False).prefixlen
    except ValueError:
        return 24


def to_cidr(ip: str, mask: str | None = None) -> str:
    if mask:
        return f"{ip}/{mask_to_cidr(mask)}"
    if "/" in ip:
        return ip
    return f"{ip}/32"


def split_tokens(line: str) -> list[str]:
    return re.split(r"\s+", line.strip())


def strip_comments(lines: list[str]) -> list[str]:
    out: list[str] = []
    for raw in lines:
        line = raw.rstrip()
        if not line or line.strip() in ("!", "#"):
            continue
        if line.strip().startswith("!"):
            continue
        out.append(line)
    return out


def collect_stanzas(lines: list[str]) -> list[tuple[str, list[str]]]:
    """
    Group config into stanzas. Top-level starters begin a new stanza;
    indented or continuation lines attach to current stanza.
    """
    starters = (
        "interface ",
        "object ",
        "object-group ",
        "access-list ",
        "access-group ",
        "route ",
        "nat ",
        "global ",
        "static ",
        "crypto ",
        "isakmp ",
        "tunnel-group ",
        "hostname ",
        "domain-name ",
        "logging ",
        "snmp-server ",
        "ntp ",
        "mtu ",
        "class-map ",
        "policy-map ",
        "service-policy ",
        "threat-detection ",
        "webvpn",
        "group-policy ",
        "dynamic-access-policy",
        "username ",
        "banner ",
        "http ",
        "ssh ",
        "telnet ",
        "icmp ",
        "dhcpd ",
        "dns ",
        "clock ",
        "failover ",
        "context ",
    )
    stanzas: list[tuple[str, list[str]]] = []
    current: list[str] = []

    def flush() -> None:
        nonlocal current
        if current:
            stanzas.append((current[0], current))
            current = []

    for line in lines:
        stripped = line.strip()
        if not stripped:
            continue
        is_top = any(stripped.startswith(s) for s in starters) and not line.startswith(" ")
        if is_top:
            flush()
            current = [stripped]
        elif current:
            current.append(stripped)
        else:
            current = [stripped]
    flush()
    return stanzas


def map_interface_name(asa_if: str) -> str:
    """Map ASA interface name to PAN ethernet naming heuristic."""
    name = asa_if
    if name.lower().startswith("gigabitethernet"):
        rest = name[len("GigabitEthernet") :]
        parts = rest.replace("/", ".").strip("/").split("/")
        if len(parts) >= 2:
            return f"ethernet1/{parts[0]}.{parts[1]}"
        if len(parts) == 1:
            return f"ethernet1/{parts[0]}"
    if name.lower().startswith("management"):
        return "management"
    if name.lower().startswith("port-channel"):
        num = re.sub(r"\D", "", name) or "1"
        return f"ae{num}"
    safe = re.sub(r"[^a-zA-Z0-9._-]", "_", name)
    return safe