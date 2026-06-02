"""End-to-end migration orchestration."""

from __future__ import annotations

from dataclasses import dataclass

from migration.detect import SourceFormat, detect_format
from migration.emit.set_emitter import emit_set_commands
from migration.emit.xml_merger import merge_into_base_xml
from migration.models.ir import MigrationIR
from migration.parsers.asa.parser import parse_asa_config
from migration.parsers.ftd_json.parser import parse_ftd_json
from migration.report import MigrationReport, Severity
from migration.resolve.build_ir import build_ir_from_asa
from migration.validate.panos_checks import validate_ir


@dataclass
class MigrationOptions:
    vsys: str = "vsys1"
    mode: str = "firewall"  # firewall | panorama
    device_group: str | None = None
    target_panos_version: str = "10.2"
    dry_run: bool = False


@dataclass
class MigrationResult:
    ir: MigrationIR
    report: MigrationReport
    set_commands: list[str]
    merged_xml: str
    set_text: str


def run_migration(
    cisco_config: str,
    base_xml: str | None = None,
    options: MigrationOptions | None = None,
) -> MigrationResult:
    opts = options or MigrationOptions()
    report = MigrationReport()
    fmt, normalized = detect_format(cisco_config)
    report.source_format = fmt.value

    if fmt == SourceFormat.UNKNOWN:
        report.add(
            Severity.BLOCKER,
            "format",
            "Could not detect Cisco config format",
            pan_hint="Provide ASA running-config, FMC ASA-syntax export, or FTD JSON",
        )
        ir = MigrationIR(vsys=opts.vsys)
    elif fmt == SourceFormat.FTD_JSON:
        ir = parse_ftd_json(normalized, report, vsys=opts.vsys)
    else:
        if fmt == SourceFormat.FMC_ASA_SYNTAX:
            report.add(Severity.AUTO, "format", "FMC ASA-syntax export detected; parsing ASA body")
        parsed = parse_asa_config(normalized)
        ir = build_ir_from_asa(parsed, report, vsys=opts.vsys)

    validate_ir(ir, report)

    set_commands = emit_set_commands(ir)
    merged_xml = merge_into_base_xml(
        base_xml,
        ir,
        mode=opts.mode,
        device_group=opts.device_group,
    )

    report.add(
        Severity.AUTO,
        "summary",
        f"Generated {len(set_commands)} SET commands, {len(ir.security_rules)} security rules, "
        f"{len(ir.nat_rules)} NAT rules, {len(ir.addresses)} addresses",
    )

    return MigrationResult(
        ir=ir,
        report=report,
        set_commands=set_commands,
        merged_xml=merged_xml,
        set_text="\n".join(set_commands) + "\n",
    )


def build_zip_bundle(result: MigrationResult) -> dict[str, str]:
    unmapped = "\n".join(result.report.unmapped_lines)
    if unmapped:
        unmapped += "\n"
    import json

    return {
        "set_commands.txt": result.set_text,
        "config_merged.xml": result.merged_xml,
        "migration_report.json": json.dumps(result.report.to_dict(), indent=2),
        "unmapped_lines.txt": unmapped or "# No unmapped lines\n",
    }