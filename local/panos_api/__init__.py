"""Read-only PAN-OS / Panorama XML API client for ADK Cyber AI.

Intentionally read-only: this package exposes keygen + operational ("op") and
config *read* calls only. There are no set/edit/delete/commit methods — the
desktop app never mutates a live device. See client.py.
"""
from .client import (
    FirewallClient,
    PanosError,
    generate_api_key,
    valid_host,
)

__all__ = ["FirewallClient", "PanosError", "generate_api_key", "valid_host"]
