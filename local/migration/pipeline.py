"""End-to-end migration pipeline: detect → parse → IR → SET/XML + report."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from migration.coverage import coverage_snapshot
from migration.emit.set_emitter import emit_set_commands
from migration.emit.xml_merger import merge_into_base_xml
from migration.models.ir import MigrationIR
from migration.parse_to_ir import parse_to_ir
from migration.report import MigrationReport, Severity
from migration.validate.panos_checks import validate_ir


@dataclass
class MigrationOptions:
    vsys: str = "vsys1"
    mode: str = "firewall"  # firewall | panorama (legacy; migration targets standalone NGFW)
    device_group: str | None = None
    source_vendor: str = "auto"  # auto|cisco|checkpoint|fortinet|juniper|palo|panorama


@dataclass
class MigrationResult:
    ir: MigrationIR
    report: MigrationReport
    set_commands: list[str]
    set_text: str
    merged_xml: str
    validation: dict[str, Any]
    summary: dict[str, Any]


def run_migration(
    source_config: str,
    base_xml: str | None = None,
    *,
    options: MigrationOptions | None = None,
) -> MigrationResult:
    opts = options or MigrationOptions()
    text = source_config
    report = MigrationReport()
    ir = parse_to_ir(
        text,
        report,
        vsys=opts.vsys,
        source_vendor=opts.source_vendor,
    )

    if opts.mode == "panorama" and opts.device_group:
        report.add(
            Severity.APPROXIMATION,
            "target",
            "Panorama device-group mode ignored; output targets standalone firewall vsys",
            pan_hint=f"Use merged XML on firewall; DG '{opts.device_group}' not applied",
        )

    set_commands = emit_set_commands(ir)
    set_text = "\n".join(set_commands) + ("\n" if set_commands else "")
    merged_xml = merge_into_base_xml(
        base_xml,
        ir,
        mode=opts.mode,
        device_group=opts.device_group,
        report=report,
    )
    validation_ok = validate_ir(ir, report)

    summary = {
        "hostname": ir.hostname,
        "vsys": ir.vsys,
        "source_vendor": ir.source_vendor,
        "source_format": report.source_format,
        "zones": len(ir.zones),
        "addresses": len(ir.addresses),
        "address_groups": len(ir.address_groups),
        "services": len(ir.services),
        "service_groups": len(ir.service_groups),
        "interfaces": len(ir.interfaces),
        "routes": len(ir.routes),
        "security_rules": len(ir.security_rules),
        "nat_rules": len(ir.nat_rules),
        "vpn_tunnels": len(ir.vpn_tunnels),
        "set_command_count": len(set_commands),
        "report": report.summary(),
        "validation_ok": validation_ok,
        "coverage": coverage_snapshot(),
    }

    return MigrationResult(
        ir=ir,
        report=report,
        set_commands=set_commands,
        set_text=set_text,
        merged_xml=merged_xml,
        validation={"ok": validation_ok},
        summary=summary,
    )


def build_zip_bundle(result: MigrationResult) -> dict[str, str]:
    import json

    return {
        "migrated_config.set": result.set_text,
        "merged_config.xml": result.merged_xml,
        "migration_report.json": json.dumps(result.report.to_dict(), indent=2),
        "migration_summary.json": json.dumps(result.summary, indent=2),
    }