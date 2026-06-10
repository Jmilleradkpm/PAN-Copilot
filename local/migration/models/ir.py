"""Canonical intermediate representation for PAN-OS emission."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field


class Zone(BaseModel):
    name: str
    security_level: int | None = None


class AddressObject(BaseModel):
    name: str
    value: str  # ip-netmask CIDR or FQDN placeholder
    description: str | None = None


class AddressGroup(BaseModel):
    name: str
    members: list[str]
    static: bool = True


class ServiceObject(BaseModel):
    name: str
    protocol: str
    port: str | None = None  # single port, range "80-443", or None for protocol-only
    source_port: str | None = None


class ServiceGroup(BaseModel):
    name: str
    members: list[str]


class InterfaceConfig(BaseModel):
    asa_name: str
    pan_name: str
    zone: str | None = None
    ip_cidr: str | None = None
    mtu: int | None = None
    comment: str | None = None


class Route(BaseModel):
    virtual_router: str = "default"
    destination: str  # CIDR
    nexthop: str | None = None
    interface: str | None = None
    metric: int | None = None


class SecurityRule(BaseModel):
    name: str
    from_zones: list[str]
    to_zones: list[str]
    source: list[str]
    destination: list[str]
    service: list[str]
    application: list[str] = Field(default_factory=lambda: ["any"])
    action: Literal["allow", "deny", "drop"] = "allow"
    disabled: bool = False
    description: str | None = None
    log_start: bool = False
    log_end: bool = False


class NatRule(BaseModel):
    name: str
    from_zones: list[str]
    to_zones: list[str]
    source: list[str]
    destination: list[str]
    service: list[str] = Field(default_factory=lambda: ["any"])
    nat_type: Literal["static", "dynamic", "dynamicip", "identity"] = "dynamic"
    translated_source: str | None = None
    translated_destination: str | None = None
    translated_port: str | None = None
    bi_directional: bool = False


class VpnTunnel(BaseModel):
    name: str
    peer_ip: str
    ike_gateway_name: str
    ipsec_profile_name: str
    local_interface: str | None = None
    psk_placeholder: str = "[PSK_REMOVED]"
    transform_hint: str | None = None


class MigrationIR(BaseModel):
    hostname: str | None = None
    vsys: str = "vsys1"
    source_vendor: str = "cisco"
    zones: list[Zone] = Field(default_factory=list)
    addresses: list[AddressObject] = Field(default_factory=list)
    address_groups: list[AddressGroup] = Field(default_factory=list)
    services: list[ServiceObject] = Field(default_factory=list)
    service_groups: list[ServiceGroup] = Field(default_factory=list)
    interfaces: list[InterfaceConfig] = Field(default_factory=list)
    routes: list[Route] = Field(default_factory=list)
    security_rules: list[SecurityRule] = Field(default_factory=list)
    nat_rules: list[NatRule] = Field(default_factory=list)
    vpn_tunnels: list[VpnTunnel] = Field(default_factory=list)