"""Detect Cisco config input format."""

from __future__ import annotations

import json
import re
from enum import Enum


class SourceFormat(str, Enum):
    ASA = "asa"
    FMC_ASA_SYNTAX = "fmc_asa_syntax"
    FTD_JSON = "ftd_json"
    UNKNOWN = "unknown"


_FMC_MARKERS = (
    re.compile(r"^!\s*FMC", re.I),
    re.compile(r"Firepower Management Center", re.I),
    re.compile(r"^!\s*Generated on:", re.I),
)


def detect_format(text: str) -> tuple[SourceFormat, str]:
    """
    Return (format, normalized_text).
    FMC ASA-syntax exports are stripped to ASA body when wrapped.
    """
    stripped = text.strip()
    if not stripped:
        return SourceFormat.UNKNOWN, text

    # Native FTD/FMC JSON export
    if stripped[0] in "{[":
        try:
            data = json.loads(stripped)
            if isinstance(data, dict) and any(
                k in data
                for k in (
                    "accessPolicies",
                    "networkObjects",
                    "portObjects",
                    "hosts",
                    "links",
                    "type",
                )
            ):
                return SourceFormat.FTD_JSON, stripped
        except json.JSONDecodeError:
            pass

    lines = text.splitlines()
    fmc_hits = sum(1 for ln in lines[:30] if any(p.search(ln) for p in _FMC_MARKERS))
    if fmc_hits >= 1:
        body = _extract_asa_body(lines)
        return SourceFormat.FMC_ASA_SYNTAX, body

    # ASA indicators
    asa_markers = (
        "access-list ",
        "object network ",
        "object-group ",
        "nameif ",
        "nat (",
        "crypto map ",
    )
    lower = text.lower()
    if any(m in lower for m in asa_markers):
        return SourceFormat.ASA, text

    if stripped.startswith("!") or "interface " in lower:
        return SourceFormat.ASA, text

    return SourceFormat.UNKNOWN, text


def _extract_asa_body(lines: list[str]) -> str:
    """Drop FMC header lines; keep ASA-style config body."""
    start = 0
    for i, ln in enumerate(lines):
        if ln.strip().startswith("interface ") or ln.strip().startswith("object "):
            start = i
            break
        if ln.strip().startswith("access-list "):
            start = i
            break
    return "\n".join(lines[start:])