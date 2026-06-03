"""Build MigrationIR from Juniper parse results."""

from __future__ import annotations

from migration.models.ir import AddressObject, MigrationIR, SecurityRule, Zone
from migration.parsers.juniper.parser import JrParseResult, ScreenParseResult
from migration.report import MigrationReport, Severity


def build_ir_from_junos(
    parsed: JrParseResult,
    report: MigrationReport,
    *,
    vsys: str = "vsys1",
) -> MigrationIR:
    ir = MigrationIR(vsys=vsys, source_vendor="juniper")

    for a in parsed.addresses:
        ir.addresses.append(AddressObject(name=a.name, value=a.ip_prefix))

    zones: set[str] = set()
    for p in parsed.policies:
        zones.add(p.from_zone)
        zones.add(p.to_zone)
        action = "allow" if p.action == "permit" else "deny"
        ir.security_rules.append(
            SecurityRule(
                name=p.name.replace("/", "_"),
                from_zones=[p.from_zone],
                to_zones=[p.to_zone],
                source=p.source,
                destination=p.destination,
                application=p.application,
                service=["application-default"],
                action=action,
            )
        )
        report.add(
            Severity.APPROXIMATION,
            "security",
            f"Junos policy '{p.name}' maps applications to service application-default",
            pan_hint="Create PAN-OS application objects or service objects for Junos apps",
        )

    for z in sorted(zones):
        ir.zones.append(Zone(name=z))

    if not parsed.policies:
        report.add(
            Severity.MANUAL_REQUIRED,
            "juniper",
            "No Junos security policies found in export",
            pan_hint="Include security { policies { from-zone ... } } section",
        )

    return ir


def build_ir_from_screenos(
    parsed: ScreenParseResult,
    report: MigrationReport,
    *,
    vsys: str = "vsys1",
) -> MigrationIR:
    ir = MigrationIR(vsys=vsys, source_vendor="juniper")
    zones: set[str] = set()

    for p in parsed.policies:
        zones.add(p.from_zone)
        zones.add(p.to_zone)
        ir.security_rules.append(
            SecurityRule(
                name=p.name,
                from_zones=[p.from_zone],
                to_zones=[p.to_zone],
                source=p.src,
                destination=p.dst,
                service=p.service,
                action="allow" if p.action == "permit" else "deny",
            )
        )

    for z in sorted(zones):
        ir.zones.append(Zone(name=z))

    if not parsed.policies:
        report.add(
            Severity.MANUAL_REQUIRED,
            "screenos",
            "No ScreenOS policies parsed",
            pan_hint="Export set policy lines or upgrade path via Junos",
        )

    return ir