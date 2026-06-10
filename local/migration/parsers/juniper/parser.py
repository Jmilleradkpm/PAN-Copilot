"""Parse Junos and ScreenOS security policy exports."""

from __future__ import annotations

import re
from dataclasses import dataclass, field


@dataclass
class JrAddress:
    name: str
    ip_prefix: str


@dataclass
class JrPolicy:
    name: str
    from_zone: str
    to_zone: str
    source: list[str] = field(default_factory=list)
    destination: list[str] = field(default_factory=list)
    application: list[str] = field(default_factory=list)
    action: str = "permit"


@dataclass
class JrParseResult:
    addresses: list[JrAddress] = field(default_factory=list)
    policies: list[JrPolicy] = field(default_factory=list)


@dataclass
class ScreenPolicy:
    name: str
    from_zone: str
    to_zone: str
    src: list[str] = field(default_factory=list)
    dst: list[str] = field(default_factory=list)
    service: list[str] = field(default_factory=list)
    action: str = "permit"


@dataclass
class ScreenParseResult:
    policies: list[ScreenPolicy] = field(default_factory=list)


_RE_ADDR = re.compile(
    r'address\s+([^\s{]+)\s+(\d+\.\d+\.\d+\.\d+/\d+);',
    re.I,
)
_RE_POLICY_BLOCK = re.compile(
    r'from-zone\s+(\S+)\s+to-zone\s+(\S+)\s*\{([^}]+)\}',
    re.S,
)
_RE_POLICY_NAME = re.compile(r'policy\s+(\S+)\s*\{', re.I)


def parse_junos_config(text: str) -> JrParseResult:
    result = JrParseResult()
    for m in _RE_ADDR.finditer(text):
        result.addresses.append(JrAddress(name=m.group(1), ip_prefix=m.group(2)))

    for zm in _RE_POLICY_BLOCK.finditer(text):
        from_z, to_z, body = zm.group(1), zm.group(2), zm.group(3)
        for pm in _RE_POLICY_NAME.finditer(body):
            pname = pm.group(1)
            chunk_start = pm.end()
            next_pm = _RE_POLICY_NAME.search(body, chunk_start)
            chunk = body[chunk_start : next_pm.start() if next_pm else len(body)]
            src = re.findall(r"source-address\s+([^;]+);", chunk)
            dst = re.findall(r"destination-address\s+([^;]+);", chunk)
            apps = re.findall(r"application\s+([^;]+);", chunk)
            action = "permit"
            if re.search(r"then\s*\{\s*deny", chunk):
                action = "deny"
            elif re.search(r"then\s*\{\s*reject", chunk):
                action = "deny"
            result.policies.append(
                JrPolicy(
                    name=pname,
                    from_zone=from_z,
                    to_zone=to_z,
                    source=[s.strip() for s in src] or ["any"],
                    destination=[d.strip() for d in dst] or ["any"],
                    application=[a.strip() for a in apps] or ["any"],
                    action=action,
                )
            )
    return result


_RE_SCREEN_POLICY = re.compile(
    r"set policy (?:from|global) (\S+) to (\S+) (\S+) (\S+) (\S+)",
    re.I,
)


def parse_screenos_config(text: str) -> ScreenParseResult:
    result = ScreenParseResult()
    for m in _RE_SCREEN_POLICY.finditer(text):
        result.policies.append(
            ScreenPolicy(
                name=f"screen_{m.start()}",
                from_zone=m.group(1),
                to_zone=m.group(2),
                src=[m.group(3)],
                dst=[m.group(4)],
                service=[m.group(5)],
                action="permit",
            )
        )
    return result