"""Emit PAN-OS SET commands from MigrationIR."""

from __future__ import annotations

from migration.models.ir import MigrationIR


def emit_set_commands(ir: MigrationIR) -> list[str]:
    lines: list[str] = []
    vsys = ir.vsys

    for z in ir.zones:
        lines.append(f"set zone {z.name} network layer3")

    for addr in ir.addresses:
        if "/" in addr.value or addr.value.replace(".", "").isdigit():
            lines.append(f"set address {addr.name} ip-netmask {addr.value}")
        else:
            lines.append(f"set address {addr.name} fqdn {addr.value}")

    for grp in ir.address_groups:
        for m in grp.members:
            lines.append(f"set address-group {grp.name} static {m}")

    for svc in ir.services:
        if svc.port:
            lines.append(f"set service {svc.name} protocol {svc.protocol} port {svc.port}")
        else:
            lines.append(f"set service {svc.name} protocol {svc.protocol}")

    for grp in ir.service_groups:
        for m in grp.members:
            lines.append(f"set service-group {grp.name} members {m}")

    for iface in ir.interfaces:
        lines.append(f"set network interface {iface.pan_name} layer3")
        if iface.ip_cidr:
            lines.append(f"set network interface {iface.pan_name} layer3 ip {iface.ip_cidr}")
        if iface.mtu:
            lines.append(f"set network interface {iface.pan_name} layer3 mtu {iface.mtu}")
        if iface.zone:
            lines.append(f"set network interface {iface.pan_name} layer3 zone {iface.zone}")
            lines.append(f"set vsys {vsys} zone {iface.zone} network layer3 {iface.pan_name}")
            lines.append(f"set vsys {vsys} import network interface {iface.pan_name}")

    for r in ir.routes:
        nh = r.nexthop or "0.0.0.0"
        lines.append(
            f"set network virtual-router {r.virtual_router} routing-table ip static-route "
            f"mig_route_{r.destination.replace('/', '_').replace('.', '_')} destination {r.destination} nexthop ip-address {nh}"
        )

    for rule in ir.security_rules:
        lines.append(f"set rulebase security rules {rule.name} from [ {' '.join(rule.from_zones)} ]")
        lines.append(f"set rulebase security rules {rule.name} to [ {' '.join(rule.to_zones)} ]")
        lines.append(f"set rulebase security rules {rule.name} source [ {' '.join(rule.source)} ]")
        lines.append(f"set rulebase security rules {rule.name} destination [ {' '.join(rule.destination)} ]")
        lines.append(f"set rulebase security rules {rule.name} service [ {' '.join(rule.service)} ]")
        lines.append(f"set rulebase security rules {rule.name} application [ {' '.join(rule.application)} ]")
        lines.append(f"set rulebase security rules {rule.name} action {rule.action}")
        if rule.disabled:
            lines.append(f"set rulebase security rules {rule.name} disabled yes")
        if rule.description:
            lines.append(f"set rulebase security rules {rule.name} description {rule.description}")

    for nat in ir.nat_rules:
        lines.append(f"set rulebase nat rules {nat.name} from [ {' '.join(nat.from_zones)} ]")
        lines.append(f"set rulebase nat rules {nat.name} to [ {' '.join(nat.to_zones)} ]")
        lines.append(f"set rulebase nat rules {nat.name} source [ {' '.join(nat.source)} ]")
        lines.append(f"set rulebase nat rules {nat.name} destination [ {' '.join(nat.destination)} ]")
        lines.append(f"set rulebase nat rules {nat.name} service [ {' '.join(nat.service)} ]")
        if nat.translated_source == "interface":
            lines.append(f"set rulebase nat rules {nat.name} source-translation interface-address interface {nat.to_zones[0] if nat.to_zones else 'any'}")
        elif nat.translated_source:
            lines.append(
                f"set rulebase nat rules {nat.name} source-translation static-ip translated-address {nat.translated_source}"
            )

    for vpn in ir.vpn_tunnels:
        lines.append(f"set network ike gateway {vpn.ike_gateway_name} peer-address ip {vpn.peer_ip}")
        lines.append(f"set network ike gateway {vpn.ike_gateway_name} authentication pre-shared-key key {vpn.psk_placeholder}")
        lines.append(f"set network ipsec crypto-profiles {vpn.ipsec_profile_name} esp encryption aes-128-cbc")
        lines.append(f"set network ipsec crypto-profiles {vpn.ipsec_profile_name} esp authentication sha1")
        lines.append(
            f"set network tunnel-ipsec {vpn.name} auto-key ike-gateway {vpn.ike_gateway_name} "
            f"ipsec-crypto-profile {vpn.ipsec_profile_name}"
        )

    return lines