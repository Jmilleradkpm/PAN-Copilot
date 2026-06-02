"""Structural validation before emitting output."""

from __future__ import annotations

from migration.models.ir import MigrationIR
from migration.report import MigrationReport, Severity


def validate_ir(ir: MigrationIR, report: MigrationReport) -> bool:
    ok = True
    addr_names = {a.name for a in ir.addresses}
    svc_names = {s.name for s in ir.services}
    zone_names = {z.name for z in ir.zones}

    for rule in ir.security_rules:
        for src in rule.source:
            if src not in ("any",) and src not in addr_names and not src.startswith("mig_"):
                if "/" not in src and not src.replace(".", "").isdigit():
                    if src not in {g.name for g in ir.address_groups}:
                        report.add(
                            Severity.APPROXIMATION,
                            "validation",
                            f"Security rule '{rule.name}' source '{src}' may be unresolved",
                        )
        for z in rule.from_zones + rule.to_zones:
            if z != "any" and z not in zone_names:
                report.add(
                    Severity.APPROXIMATION,
                    "validation",
                    f"Rule '{rule.name}' references zone '{z}' not defined from interfaces",
                )

        for svc in rule.service:
            if svc != "any" and svc not in svc_names and svc not in {g.name for g in ir.service_groups}:
                report.add(
                    Severity.APPROXIMATION,
                    "validation",
                    f"Security rule '{rule.name}' service '{svc}' may be unresolved",
                )

    for iface in ir.interfaces:
        if iface.zone and iface.zone not in zone_names:
            report.add(
                Severity.BLOCKER,
                "validation",
                f"Interface {iface.pan_name} zone '{iface.zone}' missing from zone list",
            )
            ok = False

    return ok