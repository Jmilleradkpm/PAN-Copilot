"""Palo Alto import: XML config and SET exports (Palo-to-Palo migration)."""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET

from migration.models.ir import (
    AddressObject,
    AddressGroup,
    MigrationIR,
    SecurityRule,
    ServiceObject,
    Zone,
)
from migration.report import MigrationReport, Severity


def _local(tag: str) -> str:
    return tag.split("}")[-1] if "}" in tag else tag


def _entry_name(elem: ET.Element) -> str | None:
    return elem.get("name") or elem.attrib.get("name")


def parse_panos_xml(
    text: str,
    report: MigrationReport,
    *,
    vsys: str = "vsys1",
    panorama: bool = False,
) -> MigrationIR:
    ir = MigrationIR(vsys=vsys, source_vendor="palo")
    try:
        root = ET.fromstring(text)
    except ET.ParseError as exc:
        report.add(Severity.BLOCKER, "xml", f"Invalid PAN-OS XML: {exc}")
        return ir

    if panorama:
        report.add(
            Severity.APPROXIMATION,
            "panorama",
            "Panorama XML detected — importing shared objects; map to standalone vsys manually",
            pan_hint="Use device-group extract or filter to target firewall vsys",
        )

    for entry in root.iter():
        if _local(entry.tag) != "entry":
            continue
        name = _entry_name(entry)
        if not name:
            continue
        for child in entry:
            tag = _local(child.tag)
            if tag == "ip-netmask" and child.text:
                ir.addresses.append(AddressObject(name=name, value=child.text.strip()))
            elif tag == "ip-range" and child.text:
                ir.addresses.append(AddressObject(name=name, value=child.text.strip()))
            elif tag == "fqdn" and child.text:
                ir.addresses.append(AddressObject(name=name, value=child.text.strip()))
            elif tag == "protocol" and child.get("tcp"):
                port = child.find(".//{*}port") or child.find("port")
                port_txt = port.text if port is not None and port.text else None
                ir.services.append(ServiceObject(name=name, protocol="tcp", port=port_txt))
            elif tag == "static" and list(entry):
                members = [_entry_name(m) or m.text for m in entry.findall(".//{*}member") if (m.text or m.get("name"))]
                if members:
                    ir.address_groups.append(AddressGroup(name=name, members=[str(x) for x in members if x]))

    # Security rules under rulebase
    for rules_parent in root.iter():
        if _local(rules_parent.tag) != "rules":
            continue
        for entry in rules_parent.findall(".//{*}entry"):
            rname = _entry_name(entry)
            if not rname:
                continue
            from_z = [m.text for m in entry.findall(".//{*}from/{*}member") if m.text]
            to_z = [m.text for m in entry.findall(".//{*}to/{*}member") if m.text]
            src = [m.text for m in entry.findall(".//{*}source/{*}member") if m.text]
            dst = [m.text for m in entry.findall(".//{*}destination/{*}member") if m.text]
            svc = [m.text for m in entry.findall(".//{*}service/{*}member") if m.text]
            action_el = entry.find(".//{*}action")
            action = "allow"
            if action_el is not None and action_el.text:
                action = "allow" if action_el.text.lower() == "allow" else "deny"
            ir.security_rules.append(
                SecurityRule(
                    name=rname,
                    from_zones=from_z or ["any"],
                    to_zones=to_z or ["any"],
                    source=src or ["any"],
                    destination=dst or ["any"],
                    service=svc or ["any"],
                    action=action,
                )
            )

    report.add(
        Severity.AUTO,
        "palo",
        f"Imported {len(ir.addresses)} addresses, {len(ir.security_rules)} rules from PAN-OS XML",
    )
    return ir


def parse_panos_set(
    text: str,
    report: MigrationReport,
    *,
    vsys: str = "vsys1",
) -> MigrationIR:
    """Minimal SET → IR for Palo-to-Palo re-platforming."""
    ir = MigrationIR(vsys=vsys, source_vendor="palo")
    current_addr: str | None = None
    current_rule: str | None = None
    rule_buf: dict[str, list[str] | str] = {}

    for line in text.splitlines():
        s = line.strip()
        if not s.startswith("set "):
            continue
        m = re.match(rf"set vsys {re.escape(vsys)} address ([^\s]+)", s)
        if m:
            current_addr = m.group(1)
            continue
        if current_addr and " ip-netmask " in s:
            val = s.split(" ip-netmask ", 1)[1].strip()
            ir.addresses.append(AddressObject(name=current_addr, value=val))
            current_addr = None
        m = re.match(rf"set vsys {re.escape(vsys)} rulebase security rules ([^\s]+)", s)
        if m:
            if current_rule and rule_buf:
                _flush_set_rule(ir, current_rule, rule_buf)
            current_rule = m.group(1)
            rule_buf = {}
            continue
        if current_rule:
            if " from " in s:
                rule_buf.setdefault("from", []).append(s.split(" from ", 1)[1].strip())
            if " to " in s:
                rule_buf.setdefault("to", []).append(s.split(" to ", 1)[1].strip())
            if " source " in s:
                rule_buf.setdefault("source", []).append(s.split(" source ", 1)[1].strip())
            if " destination " in s:
                rule_buf.setdefault("destination", []).append(s.split(" destination ", 1)[1].strip())
            if " service " in s:
                rule_buf.setdefault("service", []).append(s.split(" service ", 1)[1].strip())
            if " action " in s:
                rule_buf["action"] = s.split(" action ", 1)[1].strip()

    if current_rule and rule_buf:
        _flush_set_rule(ir, current_rule, rule_buf)

    report.add(
        Severity.APPROXIMATION,
        "palo",
        "SET import is partial — validate zones, NAT, and profiles in merged XML",
    )
    return ir


def _flush_set_rule(ir: MigrationIR, name: str, buf: dict) -> None:
    ir.security_rules.append(
        SecurityRule(
            name=name,
            from_zones=list(buf.get("from") or ["any"]),
            to_zones=list(buf.get("to") or ["any"]),
            source=list(buf.get("source") or ["any"]),
            destination=list(buf.get("destination") or ["any"]),
            service=list(buf.get("service") or ["any"]),
            action="allow" if str(buf.get("action", "allow")).lower() == "allow" else "deny",
        )
    )