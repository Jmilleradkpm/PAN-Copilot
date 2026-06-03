"""Dispatch vendor config text to MigrationIR."""

from __future__ import annotations

from migration.detect import VendorFormat, detect_vendor, vendor_family
from migration.models.ir import MigrationIR
from migration.parsers.asa.parser import parse_asa_config
from migration.parsers.checkpoint.parser import parse_checkpoint_config
from migration.parsers.ftd_json.parser import parse_ftd_json
from migration.parsers.fortinet.parser import parse_fortinet_config
from migration.parsers.juniper.parser import parse_junos_config, parse_screenos_config
from migration.parsers.panos.parser import parse_panos_set, parse_panos_xml
from migration.report import MigrationReport, Severity
from migration.resolve.build_ir import build_ir_from_asa
from migration.resolve.build_ir_checkpoint import build_ir_from_checkpoint
from migration.resolve.build_ir_fortinet import build_ir_from_fortinet
from migration.resolve.build_ir_juniper import build_ir_from_junos, build_ir_from_screenos


def parse_to_ir(
    source_config: str,
    report: MigrationReport,
    *,
    vsys: str = "vsys1",
    source_vendor: str = "auto",
) -> MigrationIR:
    fmt, normalized = detect_vendor(source_config, source_vendor)
    report.source_format = fmt.value
    family = vendor_family(fmt)

    if fmt == VendorFormat.UNKNOWN:
        report.add(
            Severity.BLOCKER,
            "format",
            "Could not detect vendor config format",
            pan_hint="Select vendor manually or export running config from source firewall",
        )
        return MigrationIR(vsys=vsys, source_vendor=family)

    ir: MigrationIR

    if fmt == VendorFormat.CISCO_FTD_JSON:
        ir = parse_ftd_json(normalized, report, vsys=vsys)
    elif fmt in (VendorFormat.CISCO_ASA, VendorFormat.CISCO_FMC_ASA):
        if fmt == VendorFormat.CISCO_FMC_ASA:
            report.add(Severity.AUTO, "format", "FMC ASA-syntax export; parsing ASA body")
        parsed = parse_asa_config(normalized)
        ir = build_ir_from_asa(parsed, report, vsys=vsys)
    elif fmt == VendorFormat.CHECKPOINT_R80:
        parsed = parse_checkpoint_config(normalized)
        ir = build_ir_from_checkpoint(parsed, report, vsys=vsys)
    elif fmt == VendorFormat.CHECKPOINT_LEGACY:
        report.add(
            Severity.BLOCKER,
            "checkpoint",
            "Legacy Check Point (R77/R75) export detected",
            pan_hint="Re-export from R80+ management with show configuration / mgmt_cli",
        )
        ir = MigrationIR(vsys=vsys, source_vendor="checkpoint")
    elif fmt == VendorFormat.FORTINET:
        parsed = parse_fortinet_config(normalized)
        ir = build_ir_from_fortinet(parsed, report, vsys=vsys)
    elif fmt == VendorFormat.JUNOS:
        parsed = parse_junos_config(normalized)
        ir = build_ir_from_junos(parsed, report, vsys=vsys)
    elif fmt == VendorFormat.SCREENOS:
        parsed = parse_screenos_config(normalized)
        ir = build_ir_from_screenos(parsed, report, vsys=vsys)
    elif fmt == VendorFormat.PANOS_XML:
        ir = parse_panos_xml(normalized, report, vsys=vsys)
    elif fmt == VendorFormat.PANOS_SET:
        ir = parse_panos_set(normalized, report, vsys=vsys)
    elif fmt == VendorFormat.PANORAMA_XML:
        ir = parse_panos_xml(normalized, report, vsys=vsys, panorama=True)
    else:
        ir = MigrationIR(vsys=vsys)

    ir.source_vendor = family
    return ir