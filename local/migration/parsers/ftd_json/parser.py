"""Parse FMC/FTD JSON policy export into MigrationIR."""

from __future__ import annotations

import json
from typing import Any

from migration.models.ir import AddressObject, MigrationIR, SecurityRule, ServiceObject
from migration.report import MigrationReport, Severity


def parse_ftd_json(text: str, report: MigrationReport, *, vsys: str = "vsys1") -> MigrationIR:
    data = json.loads(text)
    ir = MigrationIR(vsys=vsys)

    # FMC REST-style exports vary; support common shapes
    hosts = _collect_items(data, "hosts", "networkObjects", "objects")
    for h in hosts:
        name = h.get("name") or h.get("id")
        if not name:
            continue
        val = h.get("value") or h.get("hostIp") or h.get("overrides", {}).get("ip")
        if val:
            ir.addresses.append(AddressObject(name=str(name), value=f"{val}/32" if "/" not in str(val) else str(val)))

    ports = _collect_items(data, "ports", "portObjects")
    for p in ports:
        name = p.get("name") or p.get("id")
        if not name:
            continue
        proto = (p.get("protocol") or "tcp").lower()
        port = p.get("port") or p.get("destinationPort")
        ir.services.append(ServiceObject(name=str(name), protocol=proto, port=str(port) if port else None))

    policies = _collect_items(data, "accessPolicies", "accessControlPolicies")
    for pol in policies:
        rules = pol.get("rules") or pol.get("entries") or []
        if isinstance(rules, dict):
            rules = rules.get("items", [])
        for i, rule in enumerate(rules):
            if not isinstance(rule, dict):
                continue
            action = (rule.get("action") or rule.get("permit") or "ALLOW").upper()
            pan_action = "allow" if action in ("ALLOW", "PERMIT", True) else "deny"
            ir.security_rules.append(
                SecurityRule(
                    name=f"ftd_rule_{pol.get('name', 'policy')}_{i + 1}",
                    from_zones=["any"],
                    to_zones=["any"],
                    source=["any"],
                    destination=["any"],
                    service=["any"],
                    action=pan_action,
                    description="Migrated from FTD JSON — verify zone endpoints",
                )
            )
            report.add(
                Severity.APPROXIMATION,
                "security",
                "FTD rule zone endpoints require manual zone mapping",
                pan_hint="Map FMC zones to PAN-OS zones",
            )

    if not ir.security_rules and not ir.addresses:
        report.add(
            Severity.MANUAL_REQUIRED,
            "ftd_json",
            "FTD JSON structure not recognized; provide FMC export schema sample",
        )

    return ir


def _collect_items(data: Any, *keys: str) -> list[dict]:
    found: list[dict] = []
    if not isinstance(data, dict):
        return found
    for key in keys:
        block = data.get(key)
        if isinstance(block, list):
            found.extend(x for x in block if isinstance(x, dict))
        elif isinstance(block, dict):
            items = block.get("items") or block.get("objects") or []
            if isinstance(items, list):
                found.extend(x for x in items if isinstance(x, dict))
    return found