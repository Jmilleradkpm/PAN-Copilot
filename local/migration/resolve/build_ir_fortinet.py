"""Build MigrationIR from FortiGate parse result."""

from __future__ import annotations

from migration.models.ir import AddressObject, MigrationIR, SecurityRule, ServiceObject, Zone
from migration.parsers.fortinet.parser import FgParseResult
from migration.report import MigrationReport, Severity


def build_ir_from_fortinet(
    parsed: FgParseResult,
    report: MigrationReport,
    *,
    vsys: str = "vsys1",
) -> MigrationIR:
    ir = MigrationIR(vsys=vsys, source_vendor="fortinet")

    for a in parsed.addresses:
        val = a.subnet if "/" in a.subnet else a.subnet
        ir.addresses.append(AddressObject(name=a.name.replace(" ", "_"), value=val))

    for s in parsed.services:
        port = s.tcp_portrange or s.udp_portrange
        ir.services.append(
            ServiceObject(name=s.name.replace(" ", "_"), protocol=s.protocol, port=port)
        )

    zones_seen: set[str] = set()
    for p in parsed.policies:
        from_z = [z.replace("-", "_") for z in p.srcintf] or ["any"]
        to_z = [z.replace("-", "_") for z in p.dstintf] or ["any"]
        for z in from_z + to_z:
            if z != "any":
                zones_seen.add(z)
        action = "allow" if p.action.lower() in ("accept", "allow") else "deny"
        ir.security_rules.append(
            SecurityRule(
                name=p.name or f"fg_policy_{p.policyid}",
                from_zones=from_z,
                to_zones=to_z,
                source=p.srcaddr or ["any"],
                destination=p.dstaddr or ["any"],
                service=p.service or ["any"],
                action=action,
                disabled=p.status.lower() == "disable",
                description=f"Migrated FortiGate policy {p.policyid}",
            )
        )

    for z in sorted(zones_seen):
        ir.zones.append(Zone(name=z))

    if not parsed.policies and not parsed.addresses:
        report.add(
            Severity.MANUAL_REQUIRED,
            "fortinet",
            "No FortiGate address/policy blocks found",
            pan_hint="Paste show full-configuration or export firewall address + policy sections",
        )

    if len(parsed.policies) > 0 and not zones_seen:
        report.add(
            Severity.APPROXIMATION,
            "zones",
            "FortiGate policies parsed but interfaces missing zone mapping",
        )

    return ir