"""Feature coverage matrix for Config Migration (Expedition-style)."""

from __future__ import annotations

# Values: True = implemented in engine, False = planned, "partial" = basic support
COVERAGE_MATRIX: dict[str, dict[str, bool | str]] = {
    "cisco": {
        "objects": True,
        "groups": True,
        "services": True,
        "security": True,
        "nat": True,
        "interfaces": True,
        "routes": True,
        "vpn": True,
    },
    "checkpoint": {
        "objects": True,
        "groups": "partial",
        "services": True,
        "security": True,
        "nat": "partial",
        "interfaces": "partial",
        "routes": "partial",
        "vpn": False,
    },
    "fortinet": {
        "objects": True,
        "groups": False,
        "services": True,
        "security": True,
        "nat": False,
        "interfaces": False,
        "routes": False,
        "vpn": False,
    },
    "juniper": {
        "objects": True,
        "groups": False,
        "services": False,
        "security": True,
        "nat": False,
        "interfaces": False,
        "routes": False,
        "vpn": False,
    },
    "palo": {
        "objects": True,
        "groups": "partial",
        "services": "partial",
        "security": True,
        "nat": "partial",
        "interfaces": False,
        "routes": False,
        "vpn": False,
    },
}

FEATURE_LABELS = [
    ("objects", "Address objects"),
    ("groups", "Object groups"),
    ("services", "Services"),
    ("security", "Security policy"),
    ("nat", "NAT"),
    ("interfaces", "L3 interfaces"),
    ("routes", "Static routes"),
    ("vpn", "VPN"),
]


def coverage_for_vendor(vendor: str) -> dict[str, bool | str]:
    return COVERAGE_MATRIX.get(vendor, {})


def coverage_snapshot() -> dict:
    return {"vendors": COVERAGE_MATRIX, "features": [f[0] for f in FEATURE_LABELS]}