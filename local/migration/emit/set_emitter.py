"""Emit PAN-OS SET commands from MigrationIR (standalone NGFW / vsys scope)."""

from __future__ import annotations

from migration.models.ir import MigrationIR


def emit_set_commands(ir: MigrationIR, *, target: str = "firewall") -> list[str]:
    """
    Emit SET commands for import onto a standalone firewall.

    Vsys-scoped objects and policy use explicit `set vsys <name> ...` paths so
    commands work from device configuration context (not Panorama device-group).
    """
    lines: list[str] = []
    vsys = ir.vsys

    def vsys_set(path: str) -> str:
        return f"set vsys {vsys} {path}"

    for z in ir.zones:
        lines.append(vsys_set(f"zone {z.name} network layer3"))

    for addr in ir.addresses:
        if "/" in addr.value or addr.value.replace(".", "").isdigit():
            lines.append(vsys_set(f"address {addr.name} ip-netmask {addr.value}"))
        else:
            lines.append(vsys_set(f"address {addr.name} fqdn {addr.value}"))

    for grp in ir.address_groups:
        for m in grp.members:
            lines.append(vsys_set(f"address-group {grp.name} static {m}"))

    for svc in ir.services:
        if svc.port:
            lines.append(vsys_set(f"service {svc.name} protocol {svc.protocol} port {svc.port}"))
        else:
            lines.append(vsys_set(f"service {svc.name} protocol {svc.protocol}"))

    for grp in ir.service_groups:
        for m in grp.members:
            lines.append(vsys_set(f"service-group {grp.name} members {m}"))

    # Interfaces, virtual-router, IKE/IPsec are device-level (not vsys)
    for iface in ir.interfaces:
        lines.append(f"set network interface {iface.pan_name} layer3")
        if iface.ip_cidr:
            lines.append(f"set network interface {iface.pan_name} layer3 ip {iface.ip_cidr}")
        if iface.mtu:
            lines.append(f"set network interface {iface.pan_name} layer3 mtu {iface.mtu}")
        if iface.zone:
            lines.append(f"set network interface {iface.pan_name} layer3 zone {iface.zone}")
            lines.append(vsys_set(f"zone {iface.zone} network layer3 {iface.pan_name}"))
            lines.append(vsys_set(f"import network interface {iface.pan_name}"))

    for r in ir.routes:
        nh = r.nexthop or "0.0.0.0"
        lines.append(
            f"set network virtual-router {r.virtual_router} routing-table ip static-route "
            f"mig_route_{r.destination.replace('/', '_').replace('.', '_')} destination {r.destination} "
            f"nexthop ip-address {nh}"
        )

    for rule in ir.security_rules:
        base = f"rulebase security rules {rule.name}"
        lines.append(vsys_set(f"{base} from [ {' '.join(rule.from_zones)} ]"))
        lines.append(vsys_set(f"{base} to [ {' '.join(rule.to_zones)} ]"))
        lines.append(vsys_set(f"{base} source [ {' '.join(rule.source)} ]"))
        lines.append(vsys_set(f"{base} destination [ {' '.join(rule.destination)} ]"))
        lines.append(vsys_set(f"{base} service [ {' '.join(rule.service)} ]"))
        lines.append(vsys_set(f"{base} application [ {' '.join(rule.application)} ]"))
        lines.append(vsys_set(f"{base} action {rule.action}"))
        if rule.disabled:
            lines.append(vsys_set(f"{base} disabled yes"))
        if rule.description:
            lines.append(vsys_set(f"{base} description {rule.description}"))

    for nat in ir.nat_rules:
        base = f"rulebase nat rules {nat.name}"
        lines.append(vsys_set(f"{base} from [ {' '.join(nat.from_zones)} ]"))
        lines.append(vsys_set(f"{base} to [ {' '.join(nat.to_zones)} ]"))
        lines.append(vsys_set(f"{base} source [ {' '.join(nat.source)} ]"))
        lines.append(vsys_set(f"{base} destination [ {' '.join(nat.destination)} ]"))
        lines.append(vsys_set(f"{base} service [ {' '.join(nat.service)} ]"))
        if nat.translated_source == "interface":
            lines.append(
                vsys_set(
                    f"{base} source-translation interface-address interface "
                    f"{nat.to_zones[0] if nat.to_zones else 'any'}"
                )
            )
        elif nat.translated_source:
            lines.append(
                vsys_set(f"{base} source-translation static-ip translated-address {nat.translated_source}")
            )

    for vpn in ir.vpn_tunnels:
        lines.append(f"set network ike gateway {vpn.ike_gateway_name} peer-address ip {vpn.peer_ip}")
        lines.append(
            f"set network ike gateway {vpn.ike_gateway_name} authentication pre-shared-key key "
            f"{vpn.psk_placeholder}"
        )
        lines.append(f"set network ipsec crypto-profiles {vpn.ipsec_profile_name} esp encryption aes-128-cbc")
        lines.append(f"set network ipsec crypto-profiles {vpn.ipsec_profile_name} esp authentication sha1")
        lines.append(
            f"set network tunnel-ipsec {vpn.name} auto-key ike-gateway {vpn.ike_gateway_name} "
            f"ipsec-crypto-profile {vpn.ipsec_profile_name}"
        )

    return lines