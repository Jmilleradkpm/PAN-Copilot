"""Minimal read-only PAN-OS / Panorama XML API client.

Uses httpx (already a project dependency) rather than requests. Every method
here is read-only: keygen, operational commands, and config *reads*. There is
deliberately no set/edit/delete/commit surface — the desktop app must never
mutate a live firewall.

Design follows the ADKCyber panos-api-client conventions: a single client class
owns the host, key, and TLS setting; all user-supplied values are validated;
PAN-OS XML responses are parsed and API-level errors are raised, not swallowed.
"""
from __future__ import annotations

import ipaddress
import logging
import re
from typing import Optional
from xml.etree import ElementTree as ET

import httpx

logger = logging.getLogger("pan_copilot.panos")

# Firewalls commonly present self-signed certs. TLS verification defaults to ON;
# callers may opt out per-connection (the UI surfaces this as an explicit choice).
_DEFAULT_TIMEOUT = 30.0

# Hostname per RFC 1123 (labels of letters/digits/hyphens, max 253 chars).
_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*$"
)


class PanosError(RuntimeError):
    """Raised when the device returns a non-success API status."""


def valid_host(value: str) -> bool:
    """Accept a bare IPv4/IPv6 address or a DNS hostname. No scheme, no path."""
    if not value or "/" in value or " " in value:
        return False
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return bool(_HOSTNAME_RE.match(value))


def _parse(resp: httpx.Response) -> ET.Element:
    resp.raise_for_status()
    root = ET.fromstring(resp.text)
    if root.get("status") != "success":
        msg = root.findtext(".//msg") or root.findtext(".//line") or resp.text[:300]
        raise PanosError(f"PAN-OS API error: {msg}")
    return root


def generate_api_key(host: str, user: str, password: str, *, verify: bool = True,
                     timeout: float = _DEFAULT_TIMEOUT) -> str:
    """Exchange username/password for an API key (type=keygen). Call once.

    The password is used only for this exchange and never stored — the caller
    persists the returned key (DPAPI-wrapped), not the credentials.
    """
    if not valid_host(host):
        raise ValueError(f"Invalid firewall host: {host!r}")
    if not user or not password:
        raise ValueError("Username and password are required for keygen.")
    url = f"https://{host}/api/"
    resp = httpx.get(url, params={"type": "keygen", "user": user, "password": password},
                     verify=verify, timeout=timeout)
    root = _parse(resp)
    key = root.findtext(".//key")
    if not key:
        raise PanosError("keygen succeeded but no key was returned.")
    return key


class FirewallClient:
    """Read-only PAN-OS / Panorama XML API client."""

    def __init__(self, host: str, api_key: str, *, verify: bool = True,
                 timeout: float = _DEFAULT_TIMEOUT):
        if not valid_host(host):
            raise ValueError(f"Invalid firewall host: {host!r}")
        if not api_key:
            raise ValueError("api_key is required.")
        self.host = host
        self.api_key = api_key
        self.verify = verify
        self.timeout = timeout
        self.base = f"https://{host}/api/"
        if not verify:
            logger.warning("TLS verification disabled for %s (self-signed cert).", host)

    def _request(self, params: dict) -> ET.Element:
        params = {**params, "key": self.api_key}
        resp = httpx.get(self.base, params=params, verify=self.verify, timeout=self.timeout)
        return _parse(resp)

    # ── operational (read-only) ──────────────────────────────────────────
    def op(self, cmd_xml: str) -> ET.Element:
        """Run an operational command (show/get). Read-only, safe to run live."""
        if not cmd_xml or not cmd_xml.strip().startswith("<"):
            raise ValueError("op command must be an XML element, e.g. <show><system><info/></system></show>")
        return self._request({"type": "op", "cmd": cmd_xml})

    # ── config reads (no writes) ─────────────────────────────────────────
    def get_config(self, xpath: str, *, source: str = "running") -> ET.Element:
        """Read config at an xpath. source='running' (action=show) or
        'candidate' (action=get). No write actions are exposed."""
        if not xpath or not xpath.startswith("/"):
            raise ValueError("xpath must be an absolute /config/... path.")
        action = {"running": "show", "candidate": "get"}.get(source)
        if action is None:
            raise ValueError("source must be 'running' or 'candidate'.")
        return self._request({"type": "config", "action": action, "xpath": xpath})

    # ── convenience: parsed system info ──────────────────────────────────
    def system_info(self) -> dict:
        """Return key fields from `show system info` (version, model, serial...)."""
        root = self.op("<show><system><info></info></system></show>")
        sysnode = root.find(".//system")
        if sysnode is None:
            return {}
        fields = ("hostname", "model", "serial", "sw-version", "family",
                  "app-version", "threat-version", "uptime")
        return {f: sysnode.findtext(f) for f in fields if sysnode.findtext(f) is not None}

    def panorama_or_firewall(self) -> Optional[str]:
        """'panorama' or 'firewall' based on the system model, best-effort."""
        info = self.system_info()
        model = (info.get("model") or "").lower()
        if "panorama" in model or (info.get("family") or "").lower() == "pan-os":
            return "panorama" if "panorama" in model else "firewall"
        return "firewall" if info else None
