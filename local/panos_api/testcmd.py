"""Build PAN-OS `test` commands from structured input.

Produces both the CLI string (to copy into a console) and the XML-API `op`
element (to run live against a connected firewall). These are the everyday
"why didn't my traffic match?" checks: security-policy-match, nat-policy-match,
and routing fib-lookup.

Read-only: `test` commands evaluate policy/routing, they never change config.
"""
from __future__ import annotations

import ipaddress
from xml.sax.saxutils import escape


def _ip(value: str, field: str) -> str:
    try:
        ipaddress.ip_address(value)
    except ValueError:
        raise ValueError(f"{field} must be a valid IP address, got {value!r}")
    return value


def _port(value) -> str:
    p = int(value)
    if not 0 < p < 65536:
        raise ValueError(f"port out of range: {value}")
    return str(p)


def security_policy_match(*, source: str, destination: str, protocol="6",
                          destination_port=None, application=None) -> dict:
    """test security-policy-match — which rule a flow would hit."""
    src = _ip(source, "source")
    dst = _ip(destination, "destination")
    proto = str(int(protocol))
    parts = [f"<source>{src}</source>", f"<destination>{dst}</destination>",
             f"<protocol>{proto}</protocol>"]
    cli = f"test security-policy-match source {src} destination {dst} protocol {proto}"
    if destination_port is not None:
        dp = _port(destination_port)
        parts.append(f"<destination-port>{dp}</destination-port>")
        cli += f" destination-port {dp}"
    if application:
        app = escape(application)
        parts.append(f"<application>{app}</application>")
        cli += f" application {application}"
    op_xml = "<test><security-policy-match>" + "".join(parts) + "</security-policy-match></test>"
    return {"cli": cli, "op_xml": op_xml}


def nat_policy_match(*, source: str, destination: str, protocol="6",
                     destination_port=None, source_zone=None, to_interface=None) -> dict:
    """test nat-policy-match — which NAT rule a flow would hit."""
    src = _ip(source, "source")
    dst = _ip(destination, "destination")
    proto = str(int(protocol))
    parts = [f"<source>{src}</source>", f"<destination>{dst}</destination>",
             f"<protocol>{proto}</protocol>"]
    cli = f"test nat-policy-match source {src} destination {dst} protocol {proto}"
    if destination_port is not None:
        dp = _port(destination_port)
        parts.append(f"<destination-port>{dp}</destination-port>")
        cli += f" destination-port {dp}"
    if source_zone:
        parts.append(f"<from>{escape(source_zone)}</from>")
        cli += f" from {source_zone}"
    if to_interface:
        parts.append(f"<to-interface>{escape(to_interface)}</to-interface>")
        cli += f" to-interface {to_interface}"
    op_xml = "<test><nat-policy-match>" + "".join(parts) + "</nat-policy-match></test>"
    return {"cli": cli, "op_xml": op_xml}


def routing_fib_lookup(*, ip: str, virtual_router="default") -> dict:
    """test routing fib-lookup — egress interface/next-hop for a dest IP."""
    dst = _ip(ip, "ip")
    vr = escape(virtual_router)
    op_xml = (f"<test><routing><fib-lookup><ip>{dst}</ip>"
              f"<virtual-router>{vr}</virtual-router></fib-lookup></routing></test>")
    cli = f"test routing fib-lookup virtual-router {virtual_router} ip {dst}"
    return {"cli": cli, "op_xml": op_xml}


BUILDERS = {
    "security-policy-match": security_policy_match,
    "nat-policy-match": nat_policy_match,
    "routing-fib-lookup": routing_fib_lookup,
}


def build(kind: str, params: dict) -> dict:
    """Dispatch to a builder by kind, passing params as keyword args."""
    fn = BUILDERS.get(kind)
    if fn is None:
        raise ValueError(f"unknown test kind: {kind!r}. Options: {', '.join(BUILDERS)}")
    return fn(**params)
