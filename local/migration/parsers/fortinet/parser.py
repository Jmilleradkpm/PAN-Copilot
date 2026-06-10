"""Parse FortiGate single-VDOM configuration (show full-configuration subset)."""

from __future__ import annotations

import re
from dataclasses import dataclass, field


@dataclass
class FgAddress:
    name: str
    subnet: str  # CIDR or ip mask


@dataclass
class FgService:
    name: str
    protocol: str
    tcp_portrange: str | None = None
    udp_portrange: str | None = None


@dataclass
class FgPolicy:
    policyid: int
    name: str | None
    srcintf: list[str] = field(default_factory=list)
    dstintf: list[str] = field(default_factory=list)
    srcaddr: list[str] = field(default_factory=list)
    dstaddr: list[str] = field(default_factory=list)
    service: list[str] = field(default_factory=list)
    action: str = "accept"
    status: str = "enable"


@dataclass
class FgParseResult:
    addresses: list[FgAddress] = field(default_factory=list)
    services: list[FgService] = field(default_factory=list)
    policies: list[FgPolicy] = field(default_factory=list)


def _split_quoted_list(val: str) -> list[str]:
    return [m.strip('"') for m in re.findall(r'"([^"]*)"', val)] or [val.strip()]


def parse_fortinet_config(text: str) -> FgParseResult:
    result = FgParseResult()
    block: str | None = None
    current_addr: dict | None = None
    current_svc: dict | None = None
    current_pol: dict | None = None

    def flush_addr() -> None:
        nonlocal current_addr
        if current_addr and current_addr.get("name"):
            sub = current_addr.get("subnet", "0.0.0.0/0")
            if " " in sub and "/" not in sub:
                ip, mask = sub.split(None, 1)
                parts = mask.split(".")
                try:
                    prefix = sum(bin(int(p)).count("1") for p in parts)
                    sub = f"{ip}/{prefix}"
                except ValueError:
                    sub = f"{ip}/32"
            result.addresses.append(FgAddress(name=current_addr["name"], subnet=sub))
        current_addr = None

    def flush_svc() -> None:
        nonlocal current_svc
        if current_svc and current_svc.get("name"):
            result.services.append(
                FgService(
                    name=current_svc["name"],
                    protocol=current_svc.get("protocol", "tcp"),
                    tcp_portrange=current_svc.get("tcp-portrange"),
                    udp_portrange=current_svc.get("udp-portrange"),
                )
            )
        current_svc = None

    def flush_pol() -> None:
        nonlocal current_pol
        if current_pol and current_pol.get("policyid") is not None:
            result.policies.append(
                FgPolicy(
                    policyid=int(current_pol["policyid"]),
                    name=current_pol.get("name"),
                    srcintf=current_pol.get("srcintf", []),
                    dstintf=current_pol.get("dstintf", []),
                    srcaddr=current_pol.get("srcaddr", []),
                    dstaddr=current_pol.get("dstaddr", []),
                    service=current_pol.get("service", []),
                    action=current_pol.get("action", "accept"),
                    status=current_pol.get("status", "enable"),
                )
            )
        current_pol = None

    for line in text.splitlines():
        s = line.strip()
        if s == "config firewall address":
            block = "address"
            continue
        if s == "config firewall service custom":
            block = "service"
            continue
        if s == "config firewall policy":
            block = "policy"
            continue
        if s.startswith("config ") and block:
            if block == "address":
                flush_addr()
            elif block == "service":
                flush_svc()
            elif block == "policy":
                flush_pol()
            block = None
            continue
        if s == "end" and block:
            if block == "address":
                flush_addr()
            elif block == "service":
                flush_svc()
            elif block == "policy":
                flush_pol()
            block = None
            continue

        if block == "address":
            if s.startswith("edit "):
                flush_addr()
                m = re.match(r'edit\s+"([^"]+)"', s)
                current_addr = {"name": m.group(1) if m else s.split()[-1].strip('"')}
            elif current_addr and s.startswith("set subnet "):
                current_addr["subnet"] = s.split("set subnet ", 1)[1].strip()
            elif current_addr and s.startswith("set type fqdn"):
                current_addr["subnet"] = "0.0.0.0/0"
        elif block == "service":
            if s.startswith("edit "):
                flush_svc()
                m = re.match(r'edit\s+"([^"]+)"', s)
                current_svc = {"name": m.group(1) if m else s.split()[-1].strip('"')}
            elif current_svc and s.startswith("set tcp-portrange "):
                current_svc["tcp-portrange"] = s.split("set tcp-portrange ", 1)[1].strip()
                current_svc["protocol"] = "tcp"
            elif current_svc and s.startswith("set udp-portrange "):
                current_svc["udp-portrange"] = s.split("set udp-portrange ", 1)[1].strip()
                current_svc["protocol"] = "udp"
        elif block == "policy":
            if s.startswith("edit "):
                flush_pol()
                pid = re.match(r"edit\s+(\d+)", s)
                current_pol = {"policyid": int(pid.group(1)) if pid else 0}
            elif current_pol:
                if s.startswith("set name "):
                    current_pol["name"] = s.split("set name ", 1)[1].strip().strip('"')
                elif s.startswith("set srcintf "):
                    current_pol["srcintf"] = _split_quoted_list(s.split("set srcintf ", 1)[1])
                elif s.startswith("set dstintf "):
                    current_pol["dstintf"] = _split_quoted_list(s.split("set dstintf ", 1)[1])
                elif s.startswith("set srcaddr "):
                    current_pol["srcaddr"] = _split_quoted_list(s.split("set srcaddr ", 1)[1])
                elif s.startswith("set dstaddr "):
                    current_pol["dstaddr"] = _split_quoted_list(s.split("set dstaddr ", 1)[1])
                elif s.startswith("set service "):
                    current_pol["service"] = _split_quoted_list(s.split("set service ", 1)[1])
                elif s.startswith("set action "):
                    current_pol["action"] = s.split("set action ", 1)[1].strip()
                elif s.startswith("set status "):
                    current_pol["status"] = s.split("set status ", 1)[1].strip()

    if block == "address":
        flush_addr()
    elif block == "service":
        flush_svc()
    elif block == "policy":
        flush_pol()

    return result