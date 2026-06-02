"""Parse ASA running-config into raw structured dicts before IR resolution."""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from migration.parsers.asa.util import (
    collect_stanzas,
    mask_to_cidr,
    split_tokens,
    strip_comments,
    to_cidr,
)


@dataclass
class RawAclEntry:
    acl_name: str
    action: str
    protocol: str
    src: str
    dst: str
    service: str
    inactive: bool = False
    raw: str = ""


@dataclass
class AsaParseResult:
    hostname: str | None = None
    interfaces: list[dict] = field(default_factory=list)
    objects_network: dict[str, dict] = field(default_factory=dict)
    objects_service: dict[str, dict] = field(default_factory=dict)
    object_groups_network: dict[str, list[str]] = field(default_factory=dict)
    object_groups_service: dict[str, list[str]] = field(default_factory=dict)
    acls: list[RawAclEntry] = field(default_factory=list)
    access_groups: list[dict] = field(default_factory=list)
    routes: list[dict] = field(default_factory=list)
    nat_rules: list[dict] = field(default_factory=list)
    crypto_maps: list[dict] = field(default_factory=list)
    isakmp_policies: list[dict] = field(default_factory=list)
    tunnel_groups: dict[str, dict] = field(default_factory=dict)
    mtus: dict[str, int] = field(default_factory=dict)
    unhandled_stanzas: list[str] = field(default_factory=list)
    contexts: list[str] = field(default_factory=list)


def parse_asa_config(text: str) -> AsaParseResult:
    lines = strip_comments(text.splitlines())
    result = AsaParseResult()

    for stanza_first, stanza_lines in collect_stanzas(lines):
        key = stanza_first.split()[0] if stanza_first else ""

        if key == "hostname":
            result.hostname = stanza_first.split(maxsplit=1)[1] if len(stanza_first.split()) > 1 else None
        elif key == "interface":
            _parse_interface(stanza_lines, result)
        elif key == "object":
            _parse_object(stanza_lines, result)
        elif key == "object-group":
            _parse_object_group(stanza_lines, result)
        elif key == "access-list":
            _parse_access_list(stanza_lines, result)
        elif key == "access-group":
            _parse_access_group(stanza_first, result)
        elif key == "route":
            _parse_route(stanza_first, result)
        elif key == "nat":
            _parse_nat(stanza_first, result)
        elif key == "crypto":
            _parse_crypto(stanza_lines, result)
        elif key == "isakmp":
            _parse_isakmp(stanza_first, result)
        elif key == "tunnel-group":
            _parse_tunnel_group(stanza_lines, result)
        elif key == "mtu":
            parts = split_tokens(stanza_first)
            if len(parts) >= 3:
                result.mtus[parts[1]] = int(parts[2])
        elif key == "context":
            parts = split_tokens(stanza_first)
            if len(parts) >= 2:
                result.contexts.append(parts[1])
        else:
            result.unhandled_stanzas.append(stanza_first)

    return result


def _parse_interface(lines: list[str], result: AsaParseResult) -> None:
    parts = split_tokens(lines[0])
    if len(parts) < 2:
        return
    iface = {"name": parts[1], "nameif": None, "security_level": None, "ip": None, "mtu": None}
    for line in lines[1:]:
        tok = split_tokens(line)
        if not tok:
            continue
        if tok[0] == "nameif" and len(tok) >= 2:
            iface["nameif"] = tok[1]
        elif tok[0] == "security-level" and len(tok) >= 2:
            iface["security_level"] = int(tok[1])
        elif tok[0] == "ip" and tok[1] == "address" and len(tok) >= 4:
            iface["ip"] = to_cidr(tok[2], tok[3])
        elif tok[0] == "mtu" and len(tok) >= 2:
            iface["mtu"] = int(tok[1])
    result.interfaces.append(iface)


def _parse_object(lines: list[str], result: AsaParseResult) -> None:
    head = split_tokens(lines[0])
    if len(head) < 3:
        return
    obj_type, name = head[1], head[2]
    if obj_type == "network":
        data: dict = {"type": "network"}
        for line in lines[1:]:
            tok = split_tokens(line)
            if tok[0] == "host" and len(tok) >= 2:
                data["value"] = to_cidr(tok[1])
            elif tok[0] == "subnet" and len(tok) >= 3:
                data["value"] = to_cidr(tok[1], tok[2])
            elif tok[0] == "fqdn" and len(tok) >= 2:
                data["value"] = tok[1]
                data["fqdn"] = True
        if "value" in data:
            result.objects_network[name] = data
    elif obj_type == "service":
        data = {"protocol": "tcp", "port": None}
        for line in lines[1:]:
            tok = split_tokens(line)
            if tok[0] == "service" and len(tok) >= 2:
                data["protocol"] = tok[1]
                if "destination" in tok:
                    idx = tok.index("destination")
                    if idx + 1 < len(tok) and tok[idx + 1] == "eq" and idx + 2 < len(tok):
                        data["port"] = tok[idx + 2]
                    elif idx + 1 < len(tok) and tok[idx + 1] == "range" and idx + 3 < len(tok):
                        data["port"] = f"{tok[idx + 2]}-{tok[idx + 3]}"
        result.objects_service[name] = data


def _parse_object_group(lines: list[str], result: AsaParseResult) -> None:
    head = split_tokens(lines[0])
    if len(head) < 3:
        return
    group_type, name = head[1], head[2]
    members: list[str] = []
    for line in lines[1:]:
        tok = split_tokens(line)
        if tok[0] == "network-object" and len(tok) >= 2:
            if tok[1] == "host" and len(tok) >= 3:
                members.append(tok[2])
            elif tok[1] == "object" and len(tok) >= 3:
                members.append(tok[2])
            else:
                members.append(tok[1])
        elif tok[0] == "service-object" and len(tok) >= 2:
            if tok[1] == "object" and len(tok) >= 3:
                members.append(tok[2])
            else:
                members.append(tok[1])
        elif tok[0] == "group-object" and len(tok) >= 2:
            members.append(tok[1])
    if group_type == "network":
        result.object_groups_network[name] = members
    elif group_type == "service":
        result.object_groups_service[name] = members


def _parse_access_list(lines: list[str], result: AsaParseResult) -> None:
    for line in lines:
        inactive = "inactive" in line
        raw = line
        tok = split_tokens(line)
        if len(tok) < 5 or tok[0] != "access-list":
            continue
        acl_name = tok[1]
        # Skip standard ACLs for now
        if tok[2] not in ("extended", "advanced", "webtype"):
            result.unhandled_stanzas.append(line)
            continue
        idx = 3
        while idx < len(tok) and tok[idx] == "line":
            idx += 2
        if inactive:
            while idx < len(tok) and tok[idx] == "inactive":
                idx += 1
        if idx >= len(tok):
            continue
        action = tok[idx]
        idx += 1
        if idx >= len(tok):
            continue
        protocol = tok[idx]
        idx += 1
        src, idx = _parse_acl_endpoint(tok, idx)
        dst, idx = _parse_acl_endpoint(tok, idx)
        service = "any"
        if "eq" in tok[idx:]:
            eq_i = tok.index("eq", idx)
            if eq_i + 1 < len(tok):
                service = tok[eq_i + 1]
        elif protocol in ("tcp", "udp") and idx < len(tok):
            service = protocol
        result.acls.append(
            RawAclEntry(
                acl_name=acl_name,
                action=action,
                protocol=protocol,
                src=src,
                dst=dst,
                service=service,
                inactive=inactive,
                raw=raw,
            )
        )


def _parse_acl_endpoint(tok: list[str], idx: int) -> tuple[str, int]:
    if idx >= len(tok):
        return "any", idx
    if tok[idx] == "any":
        return "any", idx + 1
    if tok[idx] == "host" and idx + 1 < len(tok):
        return tok[idx + 1], idx + 2
    if tok[idx] == "object" and idx + 1 < len(tok):
        return tok[idx + 1], idx + 2
    if tok[idx] == "object-group" and idx + 1 < len(tok):
        return tok[idx + 1], idx + 2
    if tok[idx] == "interface":
        return tok[idx + 1] if idx + 1 < len(tok) else "any", idx + 2
    # network/mask
    if idx + 1 < len(tok) and re.match(r"\d+\.\d+\.\d+\.\d+", tok[idx]):
        return to_cidr(tok[idx], tok[idx + 1]), idx + 2
    return tok[idx], idx + 1


def _parse_access_group(line: str, result: AsaParseResult) -> None:
    tok = split_tokens(line)
    # access-group ACL_NAME in|out interface IFACE
    if len(tok) >= 5 and tok[0] == "access-group" and tok[3] == "interface":
        result.access_groups.append(
            {"acl": tok[1], "direction": tok[2], "interface": tok[4]}
        )


def _parse_route(line: str, result: AsaParseResult) -> None:
    tok = split_tokens(line)
    if len(tok) >= 5 and tok[0] == "route":
        iface, net, mask, gw = tok[1], tok[2], tok[3], tok[4]
        result.routes.append(
            {
                "interface": iface,
                "destination": to_cidr(net, mask),
                "nexthop": gw,
                "metric": int(tok[5]) if len(tok) > 5 and tok[5].isdigit() else None,
            }
        )


def _parse_nat(line: str, result: AsaParseResult) -> None:
    tok = split_tokens(line)
    m = re.search(r"\(([^,]+),([^)]+)\)", line)
    if not m:
        result.unhandled_stanzas.append(line)
        return
    src_zone, dst_zone = m.group(1), m.group(2)
    nat: dict = {"from": src_zone, "to": dst_zone, "raw": line}
    if "source static" in line:
        nat["type"] = "static"
        idx = line.find("source static") + len("source static")
        rest = split_tokens(line[idx:])
        if len(rest) >= 2:
            nat["orig"] = rest[0]
            nat["trans"] = rest[1]
    elif "source dynamic" in line:
        nat["type"] = "dynamic"
        parts = line.split("source dynamic", 1)[1].strip().split()
        if parts:
            nat["orig"] = parts[0]
            nat["trans"] = parts[1] if len(parts) > 1 else "interface"
    elif "source interface" in line:
        nat["type"] = "dynamic"
        nat["trans"] = "interface"
    else:
        nat["type"] = "unknown"
    result.nat_rules.append(nat)


def _parse_crypto(lines: list[str], result: AsaParseResult) -> None:
    for line in lines:
        tok = split_tokens(line)
        if len(tok) < 3 or tok[0] != "crypto" or tok[1] != "map":
            continue
        map_name = tok[2]
        entry = _get_or_create_crypto_map(result, map_name)
        if "set" in tok and "peer" in tok:
            peer_i = tok.index("peer")
            if peer_i + 1 < len(tok):
                entry["peer"] = tok[peer_i + 1]
        elif "ikev1" in tok and "transform-set" in tok:
            ts_i = tok.index("transform-set")
            if ts_i + 1 < len(tok):
                entry["transform"] = tok[ts_i + 1]
        elif len(tok) >= 4 and tok[3] == "interface":
            entry["interface"] = tok[4]


def _get_or_create_crypto_map(result: AsaParseResult, map_name: str) -> dict:
    for cm in result.crypto_maps:
        if cm.get("map") == map_name:
            return cm
    entry = {"map": map_name, "peer": None, "transform": None, "interface": None}
    result.crypto_maps.append(entry)
    return entry


def _parse_isakmp(line: str, result: AsaParseResult) -> None:
    tok = split_tokens(line)
    if len(tok) >= 4 and tok[0] == "isakmp" and tok[1] == "policy":
        pol_num = tok[2]
        existing = next((p for p in result.isakmp_policies if p.get("id") == pol_num), None)
        if not existing:
            existing = {"id": pol_num}
            result.isakmp_policies.append(existing)
        attr = tok[3]
        if len(tok) >= 5:
            existing[attr] = tok[4]


def _parse_tunnel_group(lines: list[str], result: AsaParseResult) -> None:
    head = split_tokens(lines[0])
    if len(head) < 2:
        return
    name = head[1]
    tg = result.tunnel_groups.setdefault(name, {"name": name, "type": None, "psk": None})
    for line in lines[1:]:
        if "pre-shared-key" in line:
            tg["psk"] = "[PSK_REMOVED]"
        tok = split_tokens(line)
        if len(tok) >= 3 and tok[0] == "type":
            tg["type"] = tok[2]