"""Build MigrationIR from ASA parse result."""

from __future__ import annotations

from migration.models.ir import (
    AddressGroup,
    AddressObject,
    InterfaceConfig,
    MigrationIR,
    NatRule,
    Route,
    SecurityRule,
    ServiceGroup,
    ServiceObject,
    VpnTunnel,
    Zone,
)
from migration.parsers.asa.parser import AsaParseResult, RawAclEntry
from migration.parsers.asa.util import map_interface_name, to_cidr
from migration.report import MigrationReport, Severity


def build_ir_from_asa(
    parsed: AsaParseResult,
    report: MigrationReport,
    *,
    vsys: str = "vsys1",
) -> MigrationIR:
    ir = MigrationIR(hostname=parsed.hostname, vsys=vsys)

    if parsed.contexts:
        report.add(
            Severity.BLOCKER,
            "context",
            f"Multi-context ASA detected ({len(parsed.contexts)} contexts). M1 supports single-context only.",
            pan_hint="Migrate each context as a separate project.",
        )

    # Zones from nameif
    zone_levels: dict[str, int] = {}
    ifname_to_zone: dict[str, str] = {}
    iface_to_zone: dict[str, str] = {}

    for iface in parsed.interfaces:
        nameif = iface.get("nameif")
        if not nameif:
            continue
        level = iface.get("security_level")
        zone_levels[nameif] = level if level is not None else 0
        ifname_to_zone[iface["name"]] = nameif
        iface_to_zone[iface["name"]] = nameif
        ir.zones.append(Zone(name=nameif, security_level=level))

    # Dedupe zones
    seen_zones: set[str] = set()
    unique_zones: list[Zone] = []
    for z in ir.zones:
        if z.name not in seen_zones:
            seen_zones.add(z.name)
            unique_zones.append(z)
    ir.zones = unique_zones

    # Address objects
    for name, data in parsed.objects_network.items():
        val = data.get("value", "")
        if data.get("fqdn"):
            report.add(
                Severity.APPROXIMATION,
                "object",
                f"FQDN object '{name}' mapped as FQDN type",
                pan_hint="Verify FQDN object on PAN-OS",
            )
            ir.addresses.append(AddressObject(name=name, value=val))
        else:
            ir.addresses.append(AddressObject(name=name, value=val))

    # Auto-create address for literal hosts in ACLs not in objects
    known_addrs = {a.name for a in ir.addresses}

    def ensure_host_object(ip: str) -> str:
        if "/" not in ip and ip.replace(".", "").isdigit():
            cidr = to_cidr(ip)
            obj_name = f"mig_host_{ip.replace('.', '_')}"
            if obj_name not in known_addrs:
                ir.addresses.append(AddressObject(name=obj_name, value=cidr))
                known_addrs.add(obj_name)
            return obj_name
        return ip

    # Service objects
    for name, data in parsed.objects_service.items():
        ir.services.append(
            ServiceObject(
                name=name,
                protocol=data.get("protocol", "tcp"),
                port=data.get("port"),
            )
        )

    # Address groups
    for name, members in parsed.object_groups_network.items():
        resolved = []
        for m in members:
            if m.replace(".", "").replace("/", "").isdigit() or "/" in m:
                resolved.append(ensure_host_object(m.split("/")[0]))
            else:
                resolved.append(m)
        ir.address_groups.append(AddressGroup(name=name, members=resolved))

    # Service groups
    for name, members in parsed.object_groups_service.items():
        ir.service_groups.append(ServiceGroup(name=name, members=members))

    # Interfaces
    for iface in parsed.interfaces:
        asa_name = iface["name"]
        pan_name = map_interface_name(asa_name)
        zone = iface.get("nameif")
        mtu = iface.get("mtu") or parsed.mtus.get(zone or "")
        ir.interfaces.append(
            InterfaceConfig(
                asa_name=asa_name,
                pan_name=pan_name,
                zone=zone,
                ip_cidr=iface.get("ip"),
                mtu=int(mtu) if mtu else None,
            )
        )

    # Routes — map ASA interface name to zone for VR (PAN uses VR not ASA iface on route)
    for r in parsed.routes:
        ir.routes.append(
            Route(
                destination=r["destination"],
                nexthop=r.get("nexthop"),
                interface=map_interface_name(r["interface"]) if r.get("interface") else None,
            )
        )

    # NAT
    for i, nat in enumerate(parsed.nat_rules):
        nat_type = nat.get("type", "unknown")
        if nat_type == "unknown":
            report.add(
                Severity.MANUAL_REQUIRED,
                "nat",
                "Unparsed NAT line requires manual conversion",
                source_line=nat.get("raw"),
            )
            continue
        orig = nat.get("orig", "any")
        if orig.startswith("obj_") or orig in parsed.objects_network:
            src_members = [orig]
        elif orig.replace(".", "").isdigit():
            src_members = [ensure_host_object(orig)]
        else:
            src_members = [orig]

        trans = nat.get("trans", "")
        translated = None
        if trans == "interface":
            translated = "interface"
            pan_nat_type = "dynamicip"
        elif trans.replace(".", "").isdigit():
            translated = ensure_host_object(trans) if trans.replace(".", "").isdigit() else trans
            pan_nat_type = "static" if nat_type == "static" else "dynamic"
        else:
            pan_nat_type = "dynamic"

        ir.nat_rules.append(
            NatRule(
                name=f"mig_nat_{i + 1}",
                from_zones=[nat.get("from", "any")],
                to_zones=[nat.get("to", "any")],
                source=src_members,
                destination=["any"],
                nat_type=pan_nat_type if pan_nat_type in ("static", "dynamic", "dynamicip", "identity") else "dynamic",
                translated_source=translated,
            )
        )

    # ACL → security rules via access-group binding
    acl_to_zone_dir: dict[str, list[tuple[str, str]]] = {}
    for ag in parsed.access_groups:
        iface_name = ag.get("interface")
        zone = ifname_to_zone.get(iface_name, iface_name)
        direction = ag.get("direction", "in")
        acl_to_zone_dir.setdefault(ag["acl"], []).append((zone, direction))

    rule_idx = 0
    for acl in parsed.acls:
        bindings = acl_to_zone_dir.get(acl.acl_name, [])
        from_zones, to_zones = _zones_from_acl_bindings(bindings, acl, report)

        src = _resolve_acl_ref(acl.src, ensure_host_object, known_addrs)
        dst = _resolve_acl_ref(acl.dst, ensure_host_object, known_addrs)
        svc = _resolve_service(acl, ir, ensure_host_object)

        action = "allow" if acl.action == "permit" else "deny"
        if acl.action == "deny" and acl.protocol == "ip" and acl.src == "any" and acl.dst == "any":
            action = "drop"

        rule_idx += 1
        ir.security_rules.append(
            SecurityRule(
                name=f"{acl.acl_name}_{rule_idx}",
                from_zones=from_zones,
                to_zones=to_zones,
                source=src,
                destination=dst,
                service=svc,
                action=action,
                disabled=acl.inactive,
                description=f"Migrated from {acl.acl_name}",
            )
        )

    # Implicit deny per zone-pair (approximation)
    report.add(
        Severity.APPROXIMATION,
        "security",
        "ASA implicit deny is not auto-inserted per zone-pair; add explicit deny rules if required.",
        pan_hint="Add bottom deny-all rules per zone pair in PAN-OS",
    )

    # VPN
    for cm in parsed.crypto_maps:
        peer = cm.get("peer")
        if not peer:
            continue
        tname = f"mig_vpn_{peer.replace('.', '_')}"
        ir.vpn_tunnels.append(
            VpnTunnel(
                name=tname,
                peer_ip=peer,
                ike_gateway_name=f"{tname}_gw",
                ipsec_profile_name=f"{tname}_ipsec",
                local_interface=map_interface_name(cm["interface"]) if cm.get("interface") else None,
                transform_hint=cm.get("transform"),
            )
        )
        if peer in parsed.tunnel_groups:
            report.add(
                Severity.AUTO,
                "vpn",
                f"Tunnel-group for peer {peer} detected; PSK stripped from output",
            )

    # Unhandled stanzas
    for line in parsed.unhandled_stanzas:
        report.unmapped_lines.append(line)
        report.add(
            Severity.MANUAL_REQUIRED,
            "unmapped",
            "Unhandled configuration line",
            source_line=line[:200],
        )

    _report_admin_features(parsed, report)
    return ir


def _zones_from_acl_bindings(
    bindings: list[tuple[str, str]],
    acl: RawAclEntry,
    report: MigrationReport,
) -> tuple[list[str], list[str]]:
    if not bindings:
        report.add(
            Severity.APPROXIMATION,
            "security",
            f"ACL '{acl.acl_name}' not bound via access-group; defaulting from/to to 'any'",
            source_line=acl.raw,
        )
        return ["any"], ["any"]

    from_z: set[str] = set()
    to_z: set[str] = set()
    for zone, direction in bindings:
        if direction == "in":
            from_z.add("any")
            to_z.add(zone)
        else:
            from_z.add(zone)
            to_z.add("any")
    return sorted(from_z) or ["any"], sorted(to_z) or ["any"]


def _resolve_acl_ref(ref: str, ensure_host, known: set[str]) -> list[str]:
    if ref == "any":
        return ["any"]
    if ref.replace(".", "").replace("/", "").isdigit() or "/" in ref:
        return [ensure_host(ref.split("/")[0] if "/" not in ref else ref)]
    return [ref]


def _resolve_service(acl: RawAclEntry, ir: MigrationIR, ensure_host) -> list[str]:
    if acl.service == "any" and acl.protocol in ("ip", "any"):
        return ["any"]
    if acl.service.isdigit():
        svc_name = f"mig_svc_{acl.protocol}_{acl.service}"
        if svc_name not in {s.name for s in ir.services}:
            ir.services.append(ServiceObject(name=svc_name, protocol=acl.protocol, port=acl.service))
        return [svc_name]
    return [acl.service]


def _report_admin_features(parsed: AsaParseResult, report: MigrationReport) -> None:
    admin_prefixes = ("logging ", "snmp-server ", "ntp ", "dhcpd ", "webvpn", "service-policy ", "threat-detection ")
    for line in parsed.unhandled_stanzas:
        if any(line.startswith(p) for p in admin_prefixes):
            report.add(
                Severity.MANUAL_REQUIRED,
                "management",
                "Management/feature stanza not auto-migrated",
                source_line=line[:120],
                pan_hint="Configure equivalent in Device Setup or profiles on PAN-OS",
            )