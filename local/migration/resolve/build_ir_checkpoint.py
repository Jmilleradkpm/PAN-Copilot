"""Build MigrationIR from Check Point parse result."""

from __future__ import annotations

from migration.models.ir import AddressObject, MigrationIR, SecurityRule, ServiceObject, Zone
from migration.parsers.checkpoint.parser import CpParseResult, network_to_cidr
from migration.report import MigrationReport, Severity


def _sanitize_name(name: str) -> str:
    return name.replace(" ", "_").replace("-", "_")


def _map_members(items: list[str], default: str = "any") -> list[str]:
    if not items:
        return [default]
    out = [_sanitize_name(x) for x in items]
    return out or [default]


def build_ir_from_checkpoint(
    parsed: CpParseResult,
    report: MigrationReport,
    *,
    vsys: str = "vsys1",
) -> MigrationIR:
    ir = MigrationIR(vsys=vsys, source_vendor="checkpoint")

    for h in parsed.hosts:
        ir.addresses.append(
            AddressObject(name=_sanitize_name(h.name), value=f"{h.ip}/32")
        )

    for n in parsed.networks:
        ir.addresses.append(
            AddressObject(name=_sanitize_name(n.name), value=network_to_cidr(n))
        )

    for s in parsed.services:
        ir.services.append(
            ServiceObject(
                name=_sanitize_name(s.name),
                protocol=s.protocol,
                port=s.port,
            )
        )

    if not parsed.rules:
        report.add(
            Severity.MANUAL_REQUIRED,
            "security",
            "No Check Point access rules parsed — verify export includes add access-rule lines",
            pan_hint="Export with mgmt_cli show configuration or SmartConsole policy package",
        )

    for i, rule in enumerate(parsed.rules):
        action = rule.action.lower()
        if action in ("accept", "allow", "permit"):
            pan_action = "allow"
        elif action in ("drop",):
            pan_action = "drop"
        else:
            pan_action = "deny"

        ir.security_rules.append(
            SecurityRule(
                name=_sanitize_name(rule.name) or f"cp_rule_{i + 1}",
                from_zones=["any"],
                to_zones=["any"],
                source=_map_members(rule.source),
                destination=_map_members(rule.destination),
                service=_map_members(rule.service),
                action=pan_action,
                disabled=rule.disabled,
                description="Migrated from Check Point — map zones manually",
            )
        )
        report.add(
            Severity.APPROXIMATION,
            "security",
            f"Check Point rule '{rule.name}' uses placeholder zones (any/any)",
            pan_hint="Assign PAN-OS from/to zones per policy layer",
        )

    if not ir.zones:
        ir.zones.append(Zone(name="trust"))
        ir.zones.append(Zone(name="untrust"))
        report.add(
            Severity.MANUAL_REQUIRED,
            "zones",
            "Check Point zones not in export; default trust/untrust placeholders added",
        )

    for line in parsed.unmapped[:50]:
        report.unmapped_lines.append(line)

    return ir