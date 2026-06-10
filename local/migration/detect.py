"""Detect vendor and config format for migration input."""

from __future__ import annotations

import json
import re
from enum import Enum


class VendorFormat(str, Enum):
    CISCO_ASA = "cisco_asa"
    CISCO_FMC_ASA = "cisco_fmc_asa_syntax"
    CISCO_FTD_JSON = "cisco_ftd_json"
    CHECKPOINT_R80 = "checkpoint_r80"
    CHECKPOINT_LEGACY = "checkpoint_legacy"
    FORTINET = "fortinet"
    JUNOS = "junos"
    SCREENOS = "screenos"
    PANOS_XML = "panos_xml"
    PANOS_SET = "panos_set"
    PANORAMA_XML = "panorama_xml"
    UNKNOWN = "unknown"


# Backward compatibility
class SourceFormat(str, Enum):
    ASA = "asa"
    FMC_ASA_SYNTAX = "fmc_asa_syntax"
    FTD_JSON = "ftd_json"
    UNKNOWN = "unknown"


_VENDOR_ALIASES = {
    "auto": None,
    "cisco": VendorFormat.CISCO_ASA,
    "checkpoint": VendorFormat.CHECKPOINT_R80,
    "fortinet": VendorFormat.FORTINET,
    "juniper": VendorFormat.JUNOS,
    "palo": VendorFormat.PANOS_XML,
    "panorama": VendorFormat.PANORAMA_XML,
}

_FMC_MARKERS = (
    re.compile(r"^!\s*FMC", re.I),
    re.compile(r"Firepower Management Center", re.I),
    re.compile(r"^!\s*Generated on:", re.I),
)


def vendor_family(fmt: VendorFormat) -> str:
    if fmt.value.startswith("cisco"):
        return "cisco"
    if fmt.value.startswith("checkpoint"):
        return "checkpoint"
    if fmt == VendorFormat.FORTINET:
        return "fortinet"
    if fmt in (VendorFormat.JUNOS, VendorFormat.SCREENOS):
        return "juniper"
    if fmt in (VendorFormat.PANOS_XML, VendorFormat.PANOS_SET, VendorFormat.PANORAMA_XML):
        return "palo"
    return "unknown"


def detect_vendor(text: str, override: str | None = None) -> tuple[VendorFormat, str]:
    """
    Return (format, normalized_text).
    override: auto|cisco|checkpoint|fortinet|juniper|palo|panorama
    """
    if override and override != "auto":
        key = override.lower().strip()
        forced = _VENDOR_ALIASES.get(key)
        if forced is not None:
            _, normalized = _detect_auto(text)
            return forced, normalized

    return _detect_auto(text)


def _detect_auto(text: str) -> tuple[VendorFormat, str]:
    stripped = text.strip()
    if not stripped:
        return VendorFormat.UNKNOWN, text

    lower = text.lower()

    # PAN-OS / Panorama XML
    if stripped.startswith("<") or "<config " in lower[:500]:
        if "device-group" in lower and "panorama" in lower:
            return VendorFormat.PANORAMA_XML, stripped
        if "<config" in lower or "<entry name=" in lower:
            return VendorFormat.PANOS_XML, stripped

    # JSON exports
    if stripped[0] in "{[":
        try:
            data = json.loads(stripped)
            if isinstance(data, dict) and any(
                k in data for k in ("accessPolicies", "networkObjects", "portObjects", "hosts")
            ):
                return VendorFormat.CISCO_FTD_JSON, stripped
        except json.JSONDecodeError:
            pass

    # FortiGate
    if "config system" in lower or "config firewall policy" in lower or "set vdom" in lower:
        return VendorFormat.FORTINET, stripped

    # Check Point
    if "add access-rule" in lower or "add host name" in lower or "mgmt_cli" in lower:
        return VendorFormat.CHECKPOINT_R80, stripped
    if "create host" in lower or "create network" in lower or "fw tab" in lower:
        return VendorFormat.CHECKPOINT_LEGACY, stripped

    # Juniper ScreenOS
    if "set policy" in lower and "set zone" in lower and "security {" not in lower:
        if "ns5gt" in lower or "screenos" in lower or re.search(r"set policy \d+", lower):
            return VendorFormat.SCREENOS, stripped

    # Junos
    if "security {" in lower or "address-book" in lower or "from-zone" in lower:
        return VendorFormat.JUNOS, stripped

    # PAN-OS SET export
    set_hits = sum(1 for ln in text.splitlines()[:200] if ln.strip().startswith("set "))
    if set_hits >= 5 and (" rulebase " in lower or " vsys " in lower or " network interface" in lower):
        return VendorFormat.PANOS_SET, stripped

    # Cisco FMC-wrapped ASA
    lines = text.splitlines()
    fmc_hits = sum(1 for ln in lines[:30] if any(p.search(ln) for p in _FMC_MARKERS))
    if fmc_hits >= 1:
        return VendorFormat.CISCO_FMC_ASA, _extract_asa_body(lines)

    asa_markers = (
        "access-list ",
        "object network ",
        "object-group ",
        "nameif ",
        "nat (",
        "crypto map ",
    )
    if any(m in lower for m in asa_markers):
        return VendorFormat.CISCO_ASA, text

    if stripped.startswith("!") or ("interface " in lower and "ip address" in lower):
        return VendorFormat.CISCO_ASA, text

    return VendorFormat.UNKNOWN, text


def detect_format(text: str) -> tuple[SourceFormat, str]:
    """Legacy Cisco-only detector."""
    fmt, normalized = detect_vendor(text)
    mapping = {
        VendorFormat.CISCO_ASA: SourceFormat.ASA,
        VendorFormat.CISCO_FMC_ASA: SourceFormat.FMC_ASA_SYNTAX,
        VendorFormat.CISCO_FTD_JSON: SourceFormat.FTD_JSON,
    }
    return mapping.get(fmt, SourceFormat.UNKNOWN), normalized


def _extract_asa_body(lines: list[str]) -> str:
    start = 0
    for i, ln in enumerate(lines):
        s = ln.strip()
        if s.startswith("interface ") or s.startswith("object ") or s.startswith("access-list "):
            start = i
            break
    return "\n".join(lines[start:])