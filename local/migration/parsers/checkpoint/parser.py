"""Parse Check Point R80+ mgmt_cli / show configuration exports."""

from __future__ import annotations

import re
from dataclasses import dataclass, field


@dataclass
class CpHost:
    name: str
    ip: str


@dataclass
class CpNetwork:
    name: str
    subnet: str
    mask: str


@dataclass
class CpService:
    name: str
    protocol: str
    port: str | None = None


@dataclass
class CpAccessRule:
    name: str
    source: list[str] = field(default_factory=list)
    destination: list[str] = field(default_factory=list)
    service: list[str] = field(default_factory=list)
    action: str = "accept"
    disabled: bool = False


@dataclass
class CpParseResult:
    hosts: list[CpHost] = field(default_factory=list)
    networks: list[CpNetwork] = field(default_factory=list)
    services: list[CpService] = field(default_factory=list)
    rules: list[CpAccessRule] = field(default_factory=list)
    unmapped: list[str] = field(default_factory=list)


_RE_HOST = re.compile(
    r'add\s+host\s+name\s+"?([^"\s]+)"?\s+ip-address\s+(\S+)',
    re.I,
)
_RE_NETWORK = re.compile(
    r'add\s+network\s+name\s+"?([^"\s]+)"?\s+subnet\s+(\S+)\s+mask\s+(\S+)',
    re.I,
)
_RE_SVC_TCP = re.compile(
    r'add\s+service-tcp\s+name\s+"?([^"\s]+)"?\s+port\s+(\S+)',
    re.I,
)
_RE_SVC_UDP = re.compile(
    r'add\s+service-udp\s+name\s+"?([^"\s]+)"?\s+port\s+(\S+)',
    re.I,
)
_RE_RULE = re.compile(
    r'add\s+access-rule\s+name\s+"?([^"\s]+)"?(.*)$',
    re.I,
)


def _mask_to_prefix(mask: str) -> int:
    parts = mask.split(".")
    if len(parts) != 4:
        return 24
    try:
        bits = sum(bin(int(p)).count("1") for p in parts)
        return bits
    except ValueError:
        return 24


def _parse_rule_tail(tail: str) -> dict[str, list[str] | str | bool]:
    out: dict[str, list[str] | str | bool] = {
        "source": [],
        "destination": [],
        "service": [],
        "action": "accept",
        "disabled": False,
    }
    for key in ("source", "destination", "service"):
        m = re.search(rf'{key}\s+"?([^"]+)"?', tail, re.I)
        if m:
            val = m.group(1).strip()
            out[key] = [v.strip() for v in re.split(r"[,\s]+", val) if v.strip()]
    act = re.search(r'action\s+"?(\w+)"?', tail, re.I)
    if act:
        out["action"] = act.group(1).lower()
    if re.search(r"disabled\s+true", tail, re.I):
        out["disabled"] = True
    return out


def parse_checkpoint_config(text: str) -> CpParseResult:
    result = CpParseResult()
    for line in text.splitlines():
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        m = _RE_HOST.search(s)
        if m:
            result.hosts.append(CpHost(name=m.group(1), ip=m.group(2)))
            continue
        m = _RE_NETWORK.search(s)
        if m:
            result.networks.append(CpNetwork(name=m.group(1), subnet=m.group(2), mask=m.group(3)))
            continue
        m = _RE_SVC_TCP.search(s)
        if m:
            result.services.append(CpService(name=m.group(1), protocol="tcp", port=m.group(2)))
            continue
        m = _RE_SVC_UDP.search(s)
        if m:
            result.services.append(CpService(name=m.group(1), protocol="udp", port=m.group(2)))
            continue
        m = _RE_RULE.search(s)
        if m:
            tail = m.group(2)
            meta = _parse_rule_tail(tail)
            result.rules.append(
                CpAccessRule(
                    name=m.group(1),
                    source=list(meta.get("source") or []),
                    destination=list(meta.get("destination") or []),
                    service=list(meta.get("service") or []),
                    action=str(meta.get("action") or "accept"),
                    disabled=bool(meta.get("disabled")),
                )
            )
            continue
        if s.lower().startswith("add ") and "access-rule" not in s.lower():
            result.unmapped.append(s)
    return result


def network_to_cidr(net: CpNetwork) -> str:
    prefix = _mask_to_prefix(net.mask)
    return f"{net.subnet}/{prefix}"