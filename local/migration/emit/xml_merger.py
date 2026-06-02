"""Merge MigrationIR into base PAN-OS XML."""

from __future__ import annotations

import xml.etree.ElementTree as ET
from xml.dom import minidom

from migration.models.ir import MigrationIR


def merge_into_base_xml(
    base_xml: str | None,
    ir: MigrationIR,
    *,
    mode: str = "firewall",
    device_group: str | None = None,
) -> str:
    if base_xml and base_xml.strip():
        root = ET.fromstring(base_xml)
    else:
        root = ET.Element("config", {"version": "10.2.0", "urldb": "paloaltonetworks"})
        devices = ET.SubElement(root, "devices")
        entry = ET.SubElement(devices, "entry", {"name": "localhost.localdomain"})
        device_config = ET.SubElement(entry, "deviceconfig")
        ET.SubElement(device_config, "system")
        vsys = ET.SubElement(entry, "vsys")
        ET.SubElement(vsys, "entry", {"name": ir.vsys})

    target = _find_target(root, mode=mode, device_group=device_group, vsys=ir.vsys)
    if target is None:
        target = _create_vsys_target(root, ir.vsys)

    _merge_addresses(target, ir)
    _merge_security_rules(target, ir)
    return _prettify(root)


def _find_target(root: ET.Element, *, mode: str, device_group: str | None, vsys: str) -> ET.Element | None:
    devices = root.find("devices")
    if devices is None:
        return None
    localhost = devices.find('.//entry[@name="localhost.localdomain"]')
    if localhost is None:
        localhost = devices.find("entry")
    if localhost is None:
        return None

    if mode == "panorama" and device_group:
        dg = localhost.find(f'.//device-group/entry[@name="{device_group}"]')
        if dg is not None:
            return dg

    vsys_entry = localhost.find(f'.//vsys/entry[@name="{vsys}"]')
    return vsys_entry


def _create_vsys_target(root: ET.Element, vsys: str) -> ET.Element:
    devices = root.find("devices")
    if devices is None:
        devices = ET.SubElement(root, "devices")
    localhost = devices.find('entry[@name="localhost.localdomain"]')
    if localhost is None:
        localhost = ET.SubElement(devices, "entry", {"name": "localhost.localdomain"})
    vsys_container = localhost.find("vsys")
    if vsys_container is None:
        vsys_container = ET.SubElement(localhost, "vsys")
    entry = vsys_container.find(f'entry[@name="{vsys}"]')
    if entry is None:
        entry = ET.SubElement(vsys_container, "entry", {"name": vsys})
    return entry


def _merge_addresses(target: ET.Element, ir: MigrationIR) -> None:
    addr_container = target.find("address")
    if addr_container is None:
        addr_container = ET.SubElement(target, "address")

    for addr in ir.addresses:
        entry = addr_container.find(f'entry[@name="{addr.name}"]')
        if entry is None:
            entry = ET.SubElement(addr_container, "entry", {"name": addr.name})
        tag = "ip-netmask" if "/" in addr.value else "fqdn"
        child = entry.find(tag)
        if child is None:
            child = ET.SubElement(entry, tag)
        child.text = addr.value


def _merge_security_rules(target: ET.Element, ir: MigrationIR) -> None:
    rulebase = target.find("rulebase")
    if rulebase is None:
        rulebase = ET.SubElement(target, "rulebase")
    security = rulebase.find("security")
    if security is None:
        security = ET.SubElement(rulebase, "security")
    rules = security.find("rules")
    if rules is None:
        rules = ET.SubElement(security, "rules")

    for rule in ir.security_rules:
        entry = rules.find(f'entry[@name="{rule.name}"]')
        if entry is None:
            entry = ET.SubElement(rules, "entry", {"name": rule.name})
        _set_members(entry, "from", rule.from_zones)
        _set_members(entry, "to", rule.to_zones)
        _set_members(entry, "source", rule.source)
        _set_members(entry, "destination", rule.destination)
        _set_members(entry, "service", rule.service)
        action = entry.find("action")
        if action is None:
            action = ET.SubElement(entry, "action")
        action.text = rule.action


def _set_members(parent: ET.Element, tag: str, values: list[str]) -> None:
    container = parent.find(tag)
    if container is None:
        container = ET.SubElement(parent, tag)
    for old in list(container.findall("member")):
        container.remove(old)
    for v in values:
        m = ET.SubElement(container, "member")
        m.text = v


def _prettify(root: ET.Element) -> str:
    rough = ET.tostring(root, encoding="unicode")
    try:
        parsed = minidom.parseString(rough)
        return parsed.toprettyxml(indent="  ")
    except Exception:
        return rough